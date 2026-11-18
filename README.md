# 🎯 Code Injection Sentinel

> A precision **Burp Suite** extension (Jython) that hunts **server-side code injection** and **Server-Side Template Injection (SSTI)** using a **math oracle** — then automatically escalates confirmed findings to **Remote Code Execution** proof.
>
> _Created by **asad0x0** — built for bug bounty & VAPT work._

![type](https://img.shields.io/badge/type-Burp%20Extension-orange)
![lang](https://img.shields.io/badge/language-Jython%202.7-blue)
![focus](https://img.shields.io/badge/focus-Code%20Injection%20%2F%20SSTI-red)
![cwe](https://img.shields.io/badge/CWE-94%20%2F%2095%20%2F%201336%20%2F%2078-critical)

---

## 📖 What it does

Most "code injection" scanners spray template payloads and flag anything that *reflects*. That produces noise — a reflected payload is not an executed one. **Code Injection Sentinel** only reports when the server actually **evaluates** your input, proven by arithmetic it could not have guessed, and then tries to turn that evaluation into a real **command-execution** proof.

- 🧠 **Math-oracle detection** — proof of *execution*, not reflection
- ✅ **Two-pair confirmation** — near-zero false positives
- 🧩 **4 engine families** — Java-EL · PHP · Python/Ruby/Node · .NET
- 🔓 **Context-breakout payloads** — fires even when input lands inside an existing tag/string
- 💥 **Automatic eval → RCE escalation** — real `id` / `ver` output as evidence
- 🔍 **Jinja2 context enumeration** — a head-start when the sandbox blocks generic gadgets
- 📊 **Report-ready output** — Payload, Evidence, CWE, Severity, CVSS per finding
- 🐞 **Burp Scanner integration** — findings land in `Target → Issues`

---

## 🧠 Methodology — the math oracle

Code injection means the payload is **executed on the server**, not echoed back. So instead of looking for our payload in the response, we inject an **arithmetic expression built from two random operands** and look for the **computed product**.

```
inject:   {{ 7193 * 3851 }}
look for: 27700143        ✅ server evaluated the expression  → code execution
          {{ 7193*3851 }} ❌ expression printed literally     → reflection only (ignored)
```

A random 7–8 digit product cannot coincidentally pre-exist on the page, and a reflected-but-not-executed payload never produces it. **The product is the proof.**

---

## ✅ Two-pair confirmation (low false positives)

A single hit could still be a fluke, so every candidate is confirmed with a **second, different** random product:

1. 🎲 Inject `a₁ * b₁` → is `product₁` in the response?
2. 🎲 Inject `a₂ * b₂` (new operands) → is `product₂` in the response?

| Result | Confidence | Row colour |
|--------|-----------|-----------|
| Both pairs match | 🟢 **CONFIRMED** | green |
| Only one pair matches | 🟡 **SUSPECTED** | yellow |

A miss costs **1 request**; a hit costs **2**. Toggle with **`Require 2-pair Confirm`**.

---

## 🛡️ False-positive controls

- 🎲 **Random multi-digit operands** — the product won't coincidentally pre-exist
- 🚫 **Baseline check** — the product must **not** already be in the original response
- 🔢 **Digit-boundary match** — the product isn't counted as a substring of a bigger number
- 🪟 **.NET culture format** — also matches the comma-grouped form `27,700,143`
- 🔁 **Two-pair confirmation** — a second random product must also compute
- 🍪 **Cookies excluded** — never scanned

---

## 🧩 Supported engines / payloads

Each payload carries two random operands (`A`, `B`); the detector searches for `A*B`. Duplicate templates across platforms are de-duplicated, so enabling all four families still sends each unique payload once.

### ☕ Java-EL  (`CWE-1336 / CWE-95`)
`${A*B}` · `#{A*B}` · `*{A*B}` · `%{A*B}` · Velocity `#set`
> EL / SpEL / OGNL / Freemarker / Velocity

### 🐘 PHP  (`CWE-95`)
`;print(A*B);` · `"-print(A*B)-"` · `'.print(A*B).'` · `${@print(A*B)}` · Smarty `{A*B}`

### 🐍 Python / Ruby / Node  (`CWE-1336 / CWE-95`)
Jinja2/Twig `{{A*B}}` · ERB `<%= A*B %>` · Ruby `#{A*B}` · Python `'+str(A*B)+'` · Node `'+(A*B)+'` · Node/JS `${A*B}`

### 🪟 .NET  (`CWE-1336 / CWE-95`)
Razor `@(A*B)` · Scriban `{{A*B}}` · Liquid `{{ A | times: B }}` · NCalc/`DataTable.Compute` bare `A*B` · classic ASP `<%= A*B %>`

> ➕ **Custom template** field: supply any template containing `__A__` and `__B__`.

---

## 🔓 Context-breakout payloads

A plain `{{A*B}}` only fires when your input lands in a **fresh** context. If it lands **inside** an existing template tag or a quoted string, you first have to close that context. These variants do exactly that:

```
}}{{A*B}}      "}}{{A*B}}      '}}{{A*B}}      (Jinja / Scriban / Razor)
"${A*B}        '${A*B}                          (Java EL out of a quoted string)
";print(A*B);//                                 (PHP out of a quoted string)
```

Toggle with **`Context Breakout`** (ON by default). CWE-tagged like any other probe.

---

## ♻️ Baseline-collision regeneration

If a random product happens to already appear in the baseline response (rare, but possible on number-heavy pages), older scanners would **skip the whole parameter** and miss a real bug. Sentinel instead **regenerates** fresh operands (up to 6 attempts) whose product is absent from the baseline — so a coincidence never costs you a finding. The second confirmation pair is also kept distinct from the first.

---

## 💥 Automatic RCE escalation (eval → command execution)

The math oracle proves *code runs*. To prove **OS command execution**, every 🟢 CONFIRMED finding automatically fires a small set of platform-aware command probes and matches the output — no manual step, fires only on an already-confirmed hit (rare), so it adds no scan noise.

| Platform | Command | Proof matched |
|----------|---------|---------------|
| 🐘 PHP | `` `id` `` via `print` / `ob_start`+`Exception` | `uid=…gid=…` |
| 🐍 Py/Ruby/Node | `os.popen('id')` · Jinja2 gadgets · Ruby `` `id` `` · Node `execSync` | `uid=…gid=…` |
| ☕ Java | Freemarker `Execute` · SpEL/OGNL + commons-io | `uid=…gid=…` |
| 🪟 .NET | `cmd /c ver` (Windows) · `/bin/sh -c id` (.NET Core) | `Microsoft Windows [Version` / `uid=…` |

On success the row is tagged **`[+RCE]`**, the Evidence becomes the live command output, the CWE gains **`+ CWE-78 (OS Command)`**, and the PoC request/response are replaced with the RCE pair. Toggle with **`Confirm RCE on hit`**.

### 🧬 Jinja2 sandbox-escape gadgets
`self.__init__.__globals__` · `cycler` · `lipsum` · `url_for` · `get_flashed_messages` · `request.application` — whichever the target exposes.

---

## 🔍 Jinja2 context enumeration (sandboxed SSTI)

Sometimes `{{7*7}}` evaluates but **every** generic RCE gadget fails — the signature of a `SandboxedEnvironment`. The real escalation then runs through an **application object** the developer left in the template context (e.g. a Pydantic model's `parse_raw` → `pickle.loads`), which no scanner can guess generically.

So when a 🟢 CONFIRMED Jinja SSTI resists the RCE gadgets, Sentinel enumerates which context objects are present using the error-free `is defined` oracle:

```
user · request · g · config · settings · session · current_app · csrf_token · app · params · current_user
```

Present objects are reported on the row (**`[ctx:manual]`** tag + Evidence `ctx: user, request, config`) so you know **exactly which object to pivot through manually**. It enumerates only — it never fires an exploit. Toggle with **`Jinja Context Enum`**.

---

## 📥 Injection points

- 🔗 **GET** URL parameters
- 📮 **POST** body parameters
- 🧾 **JSON** — recurses into every string leaf
- 📐 **XML** — every text node
- 📎 **multipart/form-data** — non-file fields
- 🍪 **Cookies** — deliberately **never** tested

---

## 🚦 Scan modes

| Mode | How |
|------|-----|
| 👂 **Passive** | Browse in-scope targets through Proxy — tested automatically |
| 📜 **Scan Proxy History** | Button — replays the whole proxy history (in-scope + testable) |
| 🗺️ **Scan Sitemap** | Button — tests the Target sitemap |
| 🖱️ **Send to Code Injection** | Right-click any request (Proxy/Repeater/Target) — forces a test, bypassing scope/MIME gates |
| ♻️ **Reset (re-scan)** | Clears the dedup cache so the same endpoints can be scanned again |

Bulk scans print an honest breakdown: `286 seen → 16 testable → N probe-requests queued`, plus *why* the rest were skipped (out-of-scope, static-ext, bad-method, not-testable-mime).

---

## 📊 Findings table & reporting

Each finding is a report-ready row:

`Time · Method · URL · Where · Engine · Payload · Confidence · Evidence · CWE · Severity · Status · Length`

- 🧾 **Payload** — the exact injected string (the PoC)
- 🔬 **Evidence** — `product=27700143 in body`, or `RCE: uid=33(www-data)…`, or `ctx: user, request`
- 🏷️ **CWE** — auto-classified: SSTI → `CWE-1336`, eval → `CWE-95`, generic → `CWE-94`, RCE → `+ CWE-78`
- ⚖️ **Severity / CVSS** — server-side code execution = **Critical 9.8** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Export CSV** includes every column plus the full CVSS vector. Row actions: **Send to Repeater / Intruder**, **Copy URL / Request**.

---

## 🐞 Burp Scanner integration

With **`Report to Scanner`** on, every finding is also pushed into **`Target → Issues`** as a custom issue (severity **High**, confidence **Certain**/**Firm**) carrying the payload, evidence, CWE and CVSS — so Burp's **own report generator** (HTML/XML) picks them up automatically, no separate CSV needed.

---

## ⚙️ Settings reference

| Setting | Default | Purpose |
|---------|---------|---------|
| Enable Extension | ✅ | Master switch |
| Platform: Java-EL / PHP / Py·Ruby·Node / .NET | ✅ | Payload families to send |
| Enable GET / POST / JSON / XML / Multipart | ✅ | Injection point sources |
| Require 2-pair Confirm | ✅ | Needs a second pair for 🟢 CONFIRMED |
| Confirm RCE on hit | ✅ | Auto eval → command-exec escalation |
| Context Breakout | ✅ | Breakout payloads for nested contexts |
| Report to Scanner | ✅ | Push findings to `Target → Issues` |
| Jinja Context Enum | ✅ | Enumerate context objects on sandboxed SSTI |
| Enable Logging / Log Misses | ✅ / ❌ | Log every probe (misses off = quiet) |
| Highlight Findings | ✅ | Colour proxy-history items |
| Custom template | — | Your own `__A__`/`__B__` payload |
| Maximum Threads | 5 | Worker pool size (applied on reload) |
| Rate limit (ms) | 120 | Minimum gap between outgoing requests |
| Ignore Extensions | css,js,png… | Static resources to skip |

---

## 📦 Installation

1. Install **Jython 2.7** standalone JAR and set it in `Extensions → Settings → Python Environment`.
2. `Extensions → Installed → Add` → Type **Python** → select `code_injection_sentinel.py`.
3. A **Code Injection** tab appears, and the loader prints to the Output pane.

> Requires **Burp Suite Professional** (uses the active scanning / Scanner-issue APIs).

---

## 🧪 Usage workflow

```
1. Target → Scope   → set your target scope
2. Browse the app   → login, forms, profile, search, templates
3. Scan Proxy History (or right-click → Send to Code Injection)
4. Read 🟢 CONFIRMED rows → check the Evidence / [+RCE] / [ctx:manual] tags
5. Send to Repeater → manually verify the PoC
6. Export CSV / Target → Issues → report
```

💡 **Where to look:** SSTI lives where input is re-rendered — profile names, bios, email/notification templates, report/PDF generators, CMS "custom template" fields.

---

## ⚠️ Limitations (honest notes)

- 🙈 **Output-based only** — no blind/OOB detection by design (keeps false positives near zero). A silent eval with no echoed result won't be seen.
- 🧮 **Bare-expression hits** (`ncalc_bare`) need manual review — a legit calculator/formula feature can evaluate `A*B` without being a security bug.
- 🧱 **Sandboxed SSTI** won't auto-RCE (correct) — use the `[ctx:manual]` enumeration to pivot by hand.
- 🏷️ **Platform grouping** — `Py/Ruby/Node` share one toggle; RCE probes for all three fire so the right one lands.

---

## 📝 CWE / CVSS mapping used

| Finding | CWE | Severity | CVSS v3.1 |
|---------|-----|----------|-----------|
| SSTI (template engine) | `CWE-1336` | Critical | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Eval / expression injection | `CWE-95` | Critical | 9.8 (same) |
| Generic code injection | `CWE-94` | Critical | 9.8 (same) |
| Escalated to command exec | `+ CWE-78` | Critical | 9.8 (same) |

---

## 👤 Author

**asad0x0** — bug bounty hunter & penetration tester.
Part of a custom Burp tooling suite (XSS Sentinel, SQLi Param Detector, LFI Sentinel, LDAP Sentinel, Endpoint Hunter, Open Redirect Hunter …).

> ⚖️ **For authorized security testing only.** Use solely against systems you have explicit permission to test.
