# JavaScript File Analysis

> Modern apps ship their API surface in JS bundles. Mining JavaScript = a free endpoint map + leaked secrets + hidden client-side logic.

## Overview

SPAs and modern frameworks push routing, API calls, and even access-control logic to the browser. Every JS file served to a user is readable by you. From JS you can extract: undiscovered API endpoints, hardcoded secrets (API keys, tokens), hidden admin features, feature flags, and sometimes the exact request shapes the server expects.

## Methodology

1. **Collect JS files** from crawling, archives, and sources
2. **Extract endpoints & parameters**
3. **Hunt secrets** with tools + manual regex
4. **Verify interesting secrets** (read-only checks only)
5. **Reverse source maps** for original source
6. **Analyze client-side logic** (feature flags, role checks, postMessage)
7. Feed endpoints into [directory fuzzing](directory-fuzzing.md) and vuln testing

## 1. Collecting JS files

### From live crawling

```bash
# katana — headless crawler with JS-file extraction
katana -u https://target.com -d 5 -jc -kf all -silent -o urls.txt
cat urls.txt | grep -Ei '\.js(\?|$)' | sort -u > js-urls.txt

# hakrawler
echo "https://target.com" | hakrawler -js -depth 3 -plain | sort -u >> js-urls.txt

# subjs — grab JS from crawled URLs
cat urls.txt | subjs >> js-urls.txt
```

### From archives (historic JS, may contain deleted endpoints/secrets)

```bash
gau target.com | grep -Ei '\.js(\?|$)' | sort -u >> js-urls.txt
echo "target.com" | waybackurls | grep -Ei '\.js' | sort -u >> js-urls.txt
```

### Download & normalize

```bash
mkdir -p js/ && cd js/
cat ../js-urls.txt | parallel -j 10 'wget -q -nc {} -O $(echo {} | md5sum | cut -d" " -f1).js'
# deobfuscate if needed (most won't be)
```

### Framework-specific paths

- **React/Next.js**: `/_next/static/chunks/`, build manifests at `/_next/static/*/buildManifest.js`
- **Webpack**: `webpack://` in sources, chunk files `*.chunk.js`
- **Vite/others**: `assets/index-*.js`

## 2. Extracting endpoints & parameters

### Tools

```bash
# LinkFinder — classic, finds URLs & paths in JS
python3 LinkFinder.py -i file.js -o cli

# xnLinkFinder — modern replacement, finds endpoints AND params
xnLinkFinder -i https://target.com -o endpoints.txt

# jsluice — best-in-class modern extractor
jsluice urls js/*.js | tee js-urls-extracted.txt
jsluice secrets js/*.js | tee js-secrets.txt

# nuclei has extraction templates too
nuclei -l js-urls.txt -t ~/nuclei-templates/exposures/ -o js-findings.txt
```

### Manual grep patterns

```bash
# API paths
grep -rhoE '["'\''`]/(api|v1|v2|graphql|internal|admin)[a-zA-Z0-9_/{}:-]*' js/ | sort -u

# fetch/axios/XHR calls
grep -rhoE '(fetch|axios|XMLHttpRequest)\(["'\''`][^"'\''`]+' js/ | sort -u

# Interesting keywords
grep -rniE '(secret|token|password|api[_-]?key|admin|debug|internal|todo|fixme)' js/
```

## 3. Hunting secrets

### Automated

```bash
# trufflehog — best overall
trufflehog filesystem ./js --only-verified=false | tee secrets.txt

# gitleaks
gitleaks dir ./js -v | tee secrets.txt

# nuclei token templates
nuclei -l js-urls.txt -t ~/nuclei-templates/exposures/tokens/generic/ -o tokens.txt
```

### Manual regex targets (the payout ones)

```regex
AKIA[0-9A-Z]{16}                    # AWS access key
AIza[0-9A-Za-z_-]{35}               # Google API key
xox[baprs]-[0-9A-Za-z-]{10,48}      # Slack tokens
sk_live_[0-9a-zA-Z]{24,}            # Stripe live key
ghp_[0-9A-Za-z]{36}                 # GitHub PAT
-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----
mongodb(\+srv)?://[^\s"']+           # Mongo URI with creds
firebaseio\.com|firebaseConfig       # Firebase config (often misconfigured DB)
sentry.io/[0-9]+                    # Sentry DSN (allows error-log abuse)
```

Search with:

```bash
grep -rhoE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,48}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9A-Za-z]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----' js/ | sort -u
```

## 4. Verifying secrets (READ-ONLY, minimum viable check)

Only non-destructive checks. For cloud keys prefer `whoami`-style calls:

```bash
# AWS key check
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity

# Slack token check (only if webhook format — posting is NOT read-only, skip if unsure)
curl -s "https://slack.com/api/auth.test" -H "Authorization: Bearer xoxb-..."

# GitHub PAT
curl -s https://api.github.com/user -H "Authorization: token ghp_..."
```

If a key is live: report it — leaked secrets with proven validity are usually critical/informational-high depending on program.

## 5. Source maps

`.js.map` files reverse minified bundles back to original source — often including comments, environment assumptions, and hardcoded values that were stripped from the build:

```bash
# Find maps
grep -rhoE '//# sourceMappingURL=[^ ]+' js/ 
# Download and extract
npx source-map-explorer file.min.js    # or: unmap, sourcemapper, source-map npm pkg
```

Check `_next/static/chunks/*.js.map` and Vite `*.js.map` — many teams ship maps to production by accident.

## 6. Client-side logic analysis

- **Feature flags / role checks**: search for `isAdmin`, `role`, `canEdit`, `featureFlags` — client-side checks can often be flipped to reveal admin-only UI and its underlying endpoints
- **postMessage listeners**: `window.addEventListener('message', ...)` — targets for [postMessage XSS](https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities) and prototype pollution chains
- **Hardcoded API structure**: request bodies in code show exactly what fields the server accepts — prime material for [mass assignment / IDOR](../vulnerabilities/idor.md) testing
- **Environment assumptions**: internal hostnames, staging URLs (`staging.api.target.com`) — add to subdomain list

## 7. What to do with extracted endpoints

1. Merge into your URL list, dedupe with `anew`
2. Probe with `httpx` — find live ones
3. Fuzz parameters on them (`arjun`, Param Miner)
4. Test authz on API-shaped endpoints → [idor.md](../vulnerabilities/idor.md), [api-testing.md](../vulnerabilities/api-testing.md)
5. Any `graphql` endpoint → introspection dump + schema review

## Tools summary

| Tool | Purpose |
|---|---|
| `katana` / `hakrawler` | Crawl + JS collection |
| `gau` / `waybackurls` | Historic JS from archives |
| `subjs` / `getJS` | JS URL extraction |
| `jsluice` | Endpoints, secrets, modern extractor |
| `xnLinkFinder` / `LinkFinder` | Endpoint extraction |
| `trufflehog` / `gitleaks` | Secret scanning |
| `nuclei` | Template-based JS findings |

## References

- [jsluice — Tom Hudson](https://github.com/BishopFox/jsluice)
- [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder)
- [JS file analysis — Hakluke (How to get started)](https://medium.com/@hakluke/how-to-analyse-javascript-for-bug-hunters-a40dd447fd55)
- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [PostMessage vulnerabilities — HackTricks](https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities)
