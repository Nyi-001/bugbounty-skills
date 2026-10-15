# Bug Hunting Methodology

> The master workflow: from choosing a program to filing a report. Read this first, then jump to the specific skill you need.

## 1. Scope first (mandatory)

1. **Confirm the target is a public program in scope.** Read the program page (HackerOne/Bugcrowd/Intigriti) before touching anything.
2. **Extract the exact scope:** in-scope domains/wildcards, out-of-scope assets, excluded vuln types (e.g. "no social engineering", "no DoS"), and the payout table.
3. **Never test out-of-scope assets.** Never run destructive/DoS actions. Respect rate limits and any time-of-day restrictions.
4. **Record scope in your working notes** so every command can be checked against it. When in doubt, ask the program first.

## 2. The workflow (order matters)

1. **Recon** → build the attack surface:
   - [Subdomain enumeration](recon/subdomain-enumeration.md) — more subdomains = more forgotten assets
   - [Directory & file fuzzing](recon/directory-fuzzing.md) — hidden endpoints, backups, configs
   - [JS file analysis](recon/js-file-analysis.md) — endpoints, secrets, hidden logic shipped to the browser
2. **Map the attack surface** — every input, endpoint, role, and trust boundary:
   - What can an unauthenticated user touch? What needs an account? What needs admin?
   - Which endpoints take IDs, files, URLs, templates?
   - What third-party services are integrated (webhooks, imports, SSO)?
3. **Test in impact order** (see table below — duplicates and payout quality matter).
4. **Validate every finding** — reproduce it, eliminate false positives, prove real impact.
5. **Write the report** → [report-writing.md](reporting/report-writing.md).

| Priority | Class | Skill file | Typical payout |
|---|---|---|---|
| 1 | Access control / IDOR | `vulnerabilities/idor.md` | Medium–Critical |
| 2 | Authentication flaws | `vulnerabilities/authentication.md` | High–Critical |
| 3 | Business logic / race conditions | `vulnerabilities/business-logic.md`, `vulnerabilities/race-conditions.md` | Medium–Critical |
| 4 | Injection (SQLi/NoSQLi/SSTI/CMD/XXE) | `vulnerabilities/` | High–Critical |
| 5 | SSRF / open redirect | `vulnerabilities/ssrf.md`, `vulnerabilities/open-redirect.md` | Medium–Critical |
| 6 | XSS / CSRF | `vulnerabilities/xss.md`, `vulnerabilities/csrf.md` | Low–High |
| 7 | API-specific (JWT, smuggling, cache) | `vulnerabilities/` | Medium–Critical |

## 3. Target selection heuristics

Prioritize programs that are:
- **Recently launched** or newly added to a platform (less picked over, fewer duplicates)
- **Large scope** with many subdomains/APIs (more forgotten assets)
- **Fintech, SaaS, healthcare** or anything with complex role/permission logic (IDOR gold)
- Non-FAANG tier — lower competition, but verify the payout actually exists

Deprioritize:
- Wildcards that resolve to nothing active
- Programs with a long "excluded" list covering exactly what you planned to test
- Assets that are third-party SaaS you can't meaningfully test

## 4. Principles

- **Impact > severity label.** An IDOR exposing another user's PII beats a self-XSS. Hunt for what causes real harm.
- **Evidence is king.** Screenshot/re-record every step, save raw HTTP request/response pairs, log exact reproduction steps. A report without a clean PoC gets closed.
- **One bug, one report.** Don't bundle unrelated findings; don't split one root cause into three reports.
- **Chain, but report the strongest link.** If low-sev A + B = critical, document the chain but file under the highest-impact result.
- **Rate-limit everything.** Add sleeps and concurrency limits to all scanners — getting your IP banned burns the whole hunt.

## 5. Toolbox

Check these are installed before a hunt (`which subfinder httpx nuclei ffuf katana dalfox sqlmap`):

- **Recon:** `subfinder`, `amass`, `assetfinder`, `httpx`, `nuclei`, `katana`, `gau`, `waybackurls`
- **Fuzzing:** `ffuf`, `gobuster`, `feroxbuster`, `wfuzz`, `kiterunner`, `arjun`
- **Exploit:** `dalfox` (XSS), `sqlmap` (SQLi), `jwt_tool`, `graphw00f`, `interactsh`/Burp Collaborator for OOB
- **Manual:** Burp Suite (Repeater, Intruder, Turbo Intruder, Autorize extension)

## 6. Working notes template

Keep a notes file per program:

```markdown
# target.com
Scope: *.target.com, api.target.com  |  Out: *.staging.target.com
Rules: no DoS, max 10 req/s, no SE
Payout: P1 $2500 / P2 $1000 / P3 $300 / P4 $100

Subdomains found: 142 live (see subs.txt)
Attack surface:
- api.target.com/v1/users/{id} — IDOR candidate, numeric IDs
- webhook import at app.target.com/import — SSRF candidate
Findings:
- [ ] IDOR on /v1/users/{id} → confirm with 2 accounts
Reports filed: none yet
```
