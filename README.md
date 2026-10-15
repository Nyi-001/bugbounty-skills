# Bug Bounty Skills 🎯

A practical, evolving playbook of bug hunting skills — methodology, reconnaissance, vulnerability testing, and report writing. Built for real bug bounty programs (HackerOne, Bugcrowd, Intigriti, YesWeHack, and VDPs).

## How to use this repo

1. Start with **[methodology.md](methodology.md)** — the master workflow: scope → recon → attack surface → testing → reporting.
2. Use the **[recon/](recon/)** skills to build the attack surface: subdomains, hidden directories, and JavaScript files.
3. Pick a vulnerability class from **[vulnerabilities/](vulnerabilities/)** and follow its methodology checklist.
4. Use **[reporting/report-writing.md](reporting/report-writing.md)** to turn confirmed findings into reports that get accepted.

## Repository structure

```
bugbounty-skills/
├── README.md                     ← you are here
├── methodology.md                ← master bug hunting workflow (read first)
├── skill-template.md             ← template for adding new skills
├── recon/
│   ├── subdomain-enumeration.md  ← find subdomains (passive + active + permutations)
│   ├── directory-fuzzing.md      ← find hidden dirs, files, endpoints, vhosts
│   └── js-file-analysis.md       ← mine JS for endpoints, secrets, hidden logic
├── vulnerabilities/
│   ├── xss.md                    ← reflected / stored / DOM / CSP bypass
│   ├── csrf.md
│   ├── open-redirect.md
│   ├── subdomain-takeover.md
│   ├── sql-injection.md
│   ├── nosql-injection.md
│   ├── ssti.md
│   ├── command-injection.md
│   ├── xxe.md
│   ├── file-upload.md
│   ├── idor.md                   ← broken access control (highest ROI)
│   ├── authentication.md         ← login bypass, password reset, 2FA/OTP
│   ├── business-logic.md
│   ├── race-conditions.md
│   ├── cors-misconfigurations.md
│   ├── ssrf.md
│   ├── api-testing.md            ← REST/GraphQL, mass assignment, rate limits
│   ├── jwt-attacks.md
│   ├── http-request-smuggling.md
│   └── cache-poisoning.md
└── reporting/
    └── report-writing.md         ← structure, severity, evidence, rejection causes
```

## Testing order (highest ROI first)

Bug bounty differs from pentest: duplicates matter and report quality determines payout. Test in this impact order:

1. **Access control / IDOR** — most common high-severity bounty
2. **Authentication flaws** — account takeover is always critical
3. **Business logic / race conditions** — no scanner finds these
4. **Injection** (SQLi / NoSQLi / SSTI / command / XXE)
5. **SSRF / open redirect**
6. **XSS / CSRF**
7. **API-specific** (GraphQL, JWT, OAuth, smuggling, cache poisoning)

## Adding a new skill

1. Copy [skill-template.md](skill-template.md).
2. Fill in every section — dense and practical beats long and vague.
3. Drop it in `recon/` or `vulnerabilities/` (or create a new category folder).
4. Add it to the structure tree above and open a PR.

## Roadmap

- [ ] One-liner command cheatsheets (fast recon pipeline)
- [ ] Working notes templates (scope tracking, finding tracker)
- [ ] GraphQL deep-dive
- [ ] OAuth/OIDC deep-dive
- [ ] Mobile app testing (APK/IPA)
- [ ] Prototype pollution & postMessage
- [ ] WAF bypass cheatsheet

## Disclaimer

For authorized security testing only. Only test assets you are explicitly allowed to test — in-scope domains of public bug bounty programs or systems you own. Never run destructive or DoS actions, respect program rate limits and rules of engagement.
