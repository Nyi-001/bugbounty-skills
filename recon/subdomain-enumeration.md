# Subdomain Enumeration

> Expand the attack surface. More subdomains = more forgotten, poorly-maintained assets = more bugs. Never test a subdomain until you confirm it's in program scope.

## Overview

Subdomain enumeration finds hosts under a target domain that aren't linked from the main site — dev/staging servers, admin panels, old WordPress installs, VPN gateways, internal tools accidentally exposed. These assets are typically less hardened and less tested than the main app, making them the single highest-ROI recon step in bug bounty.

## Methodology

1. **Passive enumeration** (no traffic to target — safe for everything)
2. **Active brute-forcing** (traffic to target — respect rate limits)
3. **Permutations/alterations** of known subdomains
4. **Resolve + filter** to unique, live hosts
5. **Probe** for web services, tech stack, and screenshots
6. **Check for takeover** opportunities
7. Feed live hosts into [directory fuzzing](directory-fuzzing.md) and [JS analysis](js-file-analysis.md)

## 1. Passive enumeration

### Certificate transparency logs

```bash
# crt.sh — free, no API key, often the single best source
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew subs.txt

# certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u | anew subs.txt
```

### Passive tools

```bash
subfinder -d target.com -all -silent | anew subs.txt        # aggregates ~50 sources
assetfinder --subs-only target.com | anew subs.txt          # fast, simple
amass enum -passive -d target.com | anew subs.txt           # slower but thorough
```

### Search engines & databases

- **Shodan**: `hostname:"target.com"` (needs API key)
- **Censys**: `services.tls.certificates.parsed.names: target.com`
- **SecurityTrails**, **DNSDumpster** (web UI), **rapiddns.io**
- **VirusTotal**: `domain:target.com` in the relations tab

### Wayback Machine & web archives

```bash
# All historic URLs — extract hostnames
echo "target.com" | waybackurls | unfurl -u format %d.%t | sort -u | anew subs.txt
gau target.com | unfurl -u domains | sort -u | anew subs.txt
```

### GitHub & code search dorking

```bash
# Subdomains leaked in code, configs, and issues
github-subdomains -d target.com -t $GITHUB_TOKEN
# Manual dorks on github.com:
#   "target.com" "api key" / *.target.com / "target.com" "internal"
```

### ASN enumeration (when scope allows org-wide)

```bash
amass intel -org "Target Inc" -max-dns-queries 200 | anew subs.txt
# From a found IP: whois 1.2.3.4 → get ASN → enumerate all hosts in the ASN
```

## 2. Active brute-forcing

Requires a solid wordlist + fast resolvers.

### Wordlists

- **SecLists**: `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- **Assetnote best-dns-wordlist**: `best-dns-wordlist.txt` (9M entries, one of the best)
- **Jason Haddix all.txt**: curated from real engagements

### Resolvers

```bash
# Public resolvers list
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
# Build your own trusted list (filters out poisoned resolvers)
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 50 -o resolvers-trusted.txt
```

### Brute force tools

```bash
# puredns (massdns wrapper) — fastest, supports wildcard filtering
puredns bruteforce wordlist.txt target.com -r resolvers.txt --wildcard-batch 1000000 -w subs-bruteforced.txt

# shuffledns
shuffledns -d target.com -w wordlist.txt -r resolvers.txt -silent -o subs-bruteforced.txt

# amass active
amass enum -active -d target.com -o subs-amass.txt
```

### Wildcard detection

If `*.target.com` resolves (check with `dig randomxyz123.target.com`), filter results:

```bash
puredns resolve subs.txt --wildcard-test -w resolved.txt
```

## 3. Permutations & alterations

Guess naming patterns from known subdomains: `api` → `api-dev`, `api.staging`, `dev-api`, `api2`...

```bash
# dnsgen — small wordlists only
dnsgen subs.txt | puredns resolve | anew subs.txt

# gotator — fast, supports depth
gotator -sub subs.txt -perm perms.txt -depth 2 -numbers 3 -md | puredns resolve | anew subs.txt

# altdns — older but reliable
altdns -i subs.txt -o permutations.txt -w words.txt -r
```

**permutation words**: `dev staging test prod api v1 v2 admin internal beta old new backup www m sandbox uat qa` (SecLists has a dedicated `alt-subnames.txt`).

## 4. Resolve & filter

```bash
# Dedupe + resolve everything
sort -u subs.txt | dnsx -silent -a -resp | anew resolved.txt

# Keep only live hosts
sort -u resolved.txt | anew final-subs.txt
```

## 5. Probe live hosts

```bash
# HTTP probing + tech detection
httpx -l final-subs.txt -silent -sc -title -td -location -fr -o live.txt

# Port scanning (top ports) on the hosts
naabu -list final-subs.txt -top-ports 1000 -silent -o ports.txt
# Follow up interesting ports with nmap:
nmap -sV -p 22,25,53,80,443,3306,8080,8443,9000 host.target.com

# Screenshots for visual triage
gowitness file live.txt
```

## 6. Subdomain takeover checks

A subdomain pointing to a dead CNAME (GitHub Pages, Heroku, S3 bucket, etc.) can often be claimed — **critical** severity.

```bash
# Automated checks
nuclei -l final-subs.txt -t ~/nuclei-templates/http/takeovers/ -o takeovers.txt
subzy run --targets final-subs.txt
# Manual guide: https://github.com/EdOverflow/can-i-take-over-xyz
```

See [subdomain-takeover.md](../vulnerabilities/subdomain-takeover.md) for the full method and service fingerprints.

## Output pipeline (one-liner)

```bash
# Passive → brute → permutations → resolve → probe, all deduped with anew
echo target.com | waybackurls | unfurl -u domains | anew subs.txt
subfinder -d target.com -all -silent | anew subs.txt
puredns bruteforce best-dns-wordlist.txt target.com -r resolvers.txt | anew subs.txt
gotator -sub subs.txt -perm perms.txt -depth 1 -md | puredns resolve | anew subs.txt
dnsx -l subs.txt -silent -a -resp -o resolved.txt
httpx -l resolved.txt -silent -sc -title -td -o live.txt
```

## Common pitfalls

- **Wildcard DNS** — everything resolves; always wildcard-test before believing results
- **Rate limits** — aggressive brute-forcing gets your IP blocked; use `-t`/`-rate` limits and time-based spreading
- **Stale subdomains** — a resolved subdomain isn't automatically live; always httpx-probe
- **Out-of-scope** — wildcard scope `*.target.com` still excludes some subdomains (often `*.staging.*`); check the program page
- **Dead CNAMEs ≠ takeover** — verify the service actually allows claiming the name (e.g. unclaimed GitHub org = no)

## Tools summary

| Tool | Purpose |
|---|---|
| `subfinder` | Passive aggregation, many sources |
| `amass` | Passive + active + intel (ASN) |
| `puredns` / `shuffledns` | Mass resolve + brute force |
| `dnsx` | Resolution, wildcard detection |
| `gotator` / `dnsgen` / `altdns` | Permutations |
| `httpx` | Live probing, tech detection |
| `naabu` / `nmap` | Port scanning |
| `nuclei` / `subzy` | Takeover detection |
| `gowitness` | Screenshots |

## References

- [Subdomain Enumeration Guide — 0xpatrik](https://0xpatrik.com/subdomain-enumeration-snippets/)
- [Trickest wordlists](https://github.com/trickest/wordlists)
- [Assetnote wordlists](https://wordlists-cdn.assetnote.io/)
- [SecLists DNS discovery](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
