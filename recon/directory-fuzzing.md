# Directory & File Fuzzing

> Hidden endpoints, backups, and forgotten files are a top source of bounty findings. Fuzz every live host found in recon.

## Overview

Directory fuzzing brute-forces paths (`/admin`, `/backup.zip`, `/api/v2/users`) against web servers and reads the response codes/sizes to discover content that isn't linked anywhere. Findings include admin panels, `.git`/`.env` exposures, backup archives, API docs, and old endpoints with weaker protections.

## Methodology

1. **Collect target URLs** (from subdomain recon + JS analysis)
2. **Base fuzz** with a small wordlist per host
3. **Extension fuzz** on interesting directories
4. **Recursive fuzz** on interesting status codes
5. **VHOST fuzzing** on wildcard domains
6. **Sensitive file checks** (`.git`, `.env`, backups)
7. **Parameter discovery** on found endpoints
8. **403 bypass** attempts on protected paths
9. Feed endpoints into vulnerability testing

## 1. Wordlists

- **SecLists**: `Discovery/Web-Content/raft-medium-directories.txt` (30k — best default), `raft-large-words.txt`, `common.txt`, `directory-list-2.3-medium.txt`
- **Assetnote httparchive** wordlists (route-heavy, API-oriented)
- **Custom**: extract words from target's own JS/HTML (see [js-file-analysis.md](js-file-analysis.md)) — target-specific words hit more often

```bash
# Generate a custom wordlist from crawled content
katana -u https://target.com -d 5 -silent -o urls.txt
cat urls.txt | unfurl -u paths | sed 's#/#\n#g' | sort -u > custom-words.txt
```

## 2. Base fuzzing

### ffuf (recommended)

```bash
# Directory fuzz, filter by status code, auto-calibrate noise
ffuf -u https://target.com/FUZZ -w raft-medium-directories.txt -mc 200,201,204,301,302,307,401,403,405,500 -ac -t 100 -o ffuf.json

# File fuzz with extensions
ffuf -u https://target.com/FUZZ -w raft-large-words.txt -e .php,.asp,.aspx,.jsp,.bak,.old,.zip,.tar.gz,.txt,.json -ac

# Fuzz at a specific depth
ffuf -u https://target.com/api/FUZZ -w assetnote-api.txt -ac
```

Key flags:
- `-ac` auto-calibrates out noise (essential — saves hours of false-positive triage)
- `-mc` match codes; `-fc`/`-fs` filter codes/sizes; `-fc 404` is the classic starter
- `-t 100` concurrency; add `-rate 50` to be polite on shared targets
- `-o out.json` + `-of json` saves results for later processing

### Alternatives

```bash
gobuster dir -u https://target.com -w raft-medium-directories.txt -t 50 -x php,html,js -o gobuster.txt -b 404
feroxbuster -u https://target.com -w raft-medium-directories.txt -t 100 -C 404 --auto-tune
dirsearch -u https://target.com -w common.txt -e php,asp,jsp -t 50 --random-agent
```

## 3. What response codes mean

| Code | Meaning | Action |
|---|---|---|
| `200` | Found | Visit it, screenshot, analyze |
| `301/302` | Redirect | Follow it — `/admin` → `/login` still reveals the path exists |
| `401/403` | Exists but protected | [403 bypass](#8-403-bypass-techniques), auth testing |
| `405` | Method not allowed | Try GET/POST/PUT/DELETE/PATCH — often reveals handlers |
| `429` | Rate limited | Slow down, note it for later |
| `500` | Server error | Note the path — often a sign of a buggy handler |

## 4. Recursive fuzzing

Once you find `/api`, `/admin`, `/v1`, fuzz *inside* them — the interesting stuff is nested:

```bash
ffuf -u https://target.com/api/FUZZ -w raft-small-words.txt -ac -recursion -recursion-depth 2
# Manual recursion: save hits, re-run against each directory found
```

## 5. VHOST discovery

Virtual hosts share an IP — the Host header selects the site. Wildcard domains hide whole apps:

```bash
# Brute-force vhosts: filter by default response size
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w subdomains-top1million-5000.txt -fs 612 -ac
# Also try the bare IP as target and wildcard hosts
ffuf -u http://1.2.3.4 -H "Host: FUZZ.target.com" -w wordlist.txt -fs 612
```

## 6. Sensitive files

```bash
# Automated checks with nuclei
nuclei -l live.txt -t ~/nuclei-templates/exposures/ -o exposures.txt
nuclei -t ~/nuclei-templates/exposures/configs/ -u https://target.com

# Manual paths to try on every host:
# /.git/config  /.git/HEAD  /.svn/entries  /.env  /.env.bak  /.env.local
# /.aws/credentials  /.htaccess  /config.php.bak  /backup.zip  /db.sql
# /sitemap.xml  /robots.txt  /crossdomain.xml  /security.txt
```

- `/.git/config` exposed → `git-dumper https://target.com/.git/` → full source code → source review for secrets and bugs (often critical alone)
- `/sitemap.xml` and `/robots.txt` — always read them first; they hand you paths for free

## 7. Parameter discovery

Found an endpoint but no params? Mine the app's own JS, or brute-force:

```bash
arjun -u https://target.com/endpoint -t 50
# Burp: Intruder + the Param Miner extension — very effective
# x8 for fast param fuzzing
x8 -u "https://target.com/endpoint" -w params.txt
```

## 8. 403 bypass techniques

Try each on a 403 path, one at a time:

```bash
# Header tricks
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1

# Path tricks (request path variants)
/admin/..;/admin   /admin%2e  /admin%20  /admin%09  /./admin  /admin/.  /admin//

# Case & encoding
/Admin  /ADMIN  /%61dmin  /ad%6din  /admin%252e

# Method & protocol tricks
GET /admin → POST /admin  →  HEAD /admin
GET /admin HTTP/1.1 → HTTP/2 (or downgrade to HTTP/1.0)
```

Automate with [byp4xx](https://github.com/lobuhi/byp4xx) — it tries all of these in one pass.

## 9. API endpoint discovery

Wordlists are path-oriented; APIs need route fuzzing:

```bash
# kiterunner — built for API routes (Rails, Express, Spring, FastAPI wordlists)
kr scan https://target.com -w routes-large.kite -x 50 -o kr.txt
```

## Tools summary

| Tool | Strength |
|---|---|
| `ffuf` | Fast, `-ac` auto-calibration, recursion |
| `feroxbuster` | Recursion + `--auto-tune` |
| `gobuster` | Simple, reliable |
| `dirsearch` | Good default wordlist handling |
| `kiterunner` | API route fuzzing |
| `arjun` / `x8` | Parameter discovery |
| `nuclei` | Sensitive file exposures |
| `byp4xx` | 403 bypass attempts |

## References

- [FFuF docs](https://github.com/ffuf/ffuf)
- [SecLists Web-Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
- [Assetnote wordlists](https://wordlists-cdn.assetnote.io/)
- [403 bypass research — PortSwigger](https://portswigger.net/research/403-bypass)
- [kiterunner](https://github.com/assetnote/kiterunner)
