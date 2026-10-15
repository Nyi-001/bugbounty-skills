# Report Writing

> A great bug with a bad report gets closed as N/A. The report is the product — write it like the triager's time is worth more than yours.

## Overview

Bug bounty reports are read by triagers who see hundreds per week. They decide in ~2 minutes whether your finding gets forwarded, closed as duplicate, or dismissed as N/A. A clean, reproducible report with an undeniable PoC is the difference between a payout and a rejection.

## Report structure

```markdown
## Title: [Vuln class] on [asset] allows [impact] — [one line, specific]

**Severity:** High (CVSS 7.5)

**Affected asset:** https://target.com/endpoint

## Summary
2-3 sentences. What's broken, what an attacker achieves, who's affected.
No jargon, no theory.

## Steps to reproduce
1. Register account A and account B
2. As A, visit https://target.com/...
3. Intercept request, change `user_id=123` to `user_id=124`
4. Observe account B's data in the response (see screenshot)

## PoC
- Screenshot/video of the impact
- Raw HTTP request/response pairs
- Exact payload used

## Impact
Account B's PII (email, address, payment methods) is exposed to any
authenticated user by changing one integer. Affects all N million users.

## Remediation
Enforce object-level authorization checks server-side; use UUIDs for
object references; add automated authz tests.
```

### What each section must do

- **Title** — triagers browse titles first; "IDOR on /api/v1/orders allows viewing any user's order history" beats "IDOR found"
- **Summary** — the who/what/so-what in plain language; assume the reader hasn't seen the bug
- **Steps to reproduce** — numbered, copy-pasteable, no steps skipped; a triager must reproduce it in one attempt
- **PoC** — screenshots of the actual impact, not just the payload; video for multi-step chains
- **Impact** — quantify: how many users, what data, what an attacker does next
- **Remediation** — one paragraph, actionable; shows you understand the fix (some programs pay more for good remediation)

## Severity guidance

Use the program's own rating where defined. Otherwise as a rough baseline:

| Class | Typical range |
|---|---|
| RCE, subdomain takeover with proof, critical auth bypass | Critical |
| SQLi (data exfil), full ATO, SSRF to cloud metadata | High |
| IDOR on sensitive data, stored XSS on main app, authz bypass | Medium–High |
| Reflected XSS, CSRF on key actions, open redirect | Medium |
| Low-impact info leaks, missing headers | Low–Informational |

**CVSS 3.1** — compute it (first.org/cvss/calculator) and include the vector string; triagers trust reports that show their work. If you over-rate a finding, everything else in the report loses credibility.

## Evidence rules

- **Screenshot everything** — impact page, request/response in Burp, collaborator interaction IDs with timestamps
- **Save raw requests** — export from Burp as `.req`/`.resp` files or paste verbatim in code blocks
- **Record video** for flows with many steps (OAuth chains, business logic)
- **Fresh session** — reproduce with clean cookies/new accounts so "it only worked because of your extensions" can't be claimed
- **For blind/OOB vulns** — include the full collaborator log: interaction type, timestamp, and the exact payload that caused it

## One bug, one report

- **Don't bundle** — two unrelated IDORs in one report get the lower payout and annoy triagers
- **Don't split** — one root cause hitting 10 endpoints is one report listing all 10
- **Chain, but file under the strongest link** — "open redirect + OAuth token leak" is one report titled as account takeover, with the chain documented

## Common rejection causes (avoid these)

| Reason | Prevention |
|---|---|
| Duplicate | Search existing reports first; check the program's disclosed reports; hunt fresher targets |
| No security impact | Self-XSS, missing headers, clickjacking on a page with nothing to click — don't file these unless the program explicitly pays |
| Not reproducible | Test your own steps in a clean browser before submitting |
| Out of scope | Read the scope page carefully; some assets/vuln classes are excluded |
| Rate limiting / scanner output only | Raw scanner dumps without manual confirmation get closed |
| The "informational" trap | Prove impact or don't file — one-line "we recommend hardening" findings waste everyone's time |

## Platform notes

- **HackerOne** — severity is CVSS-based; use the calculator, reference CWE; triagers expect the report template above
- **Bugcrowd** — has its own VRT (Vulnerability Rating Taxonomy); map your finding to the VRT category and priority
- **Intigriti** — often faster triage; same report standards
- **Duplicates on busy programs** — if you're late to a well-known bug, your report must show deeper impact (more data, more users, a bypass of their fix)

## After submission

- Reply to triager questions within hours — responsiveness is factored into reputation
- If closed as N/A and you disagree, ask politely with new evidence, not a wall of text
- Request CVE/CWE mapping if relevant; keep the report updated if the program asks for changes
- Log what you learned — a closed-duplicate still teaches you what was already known, which sharpens the next hunt

## References

- [HackerOne disclosure guidelines](https://hackerone.com/disclosure-guidelines)
- [CVSS 3.1 calculator](https://www.first.org/cvss/calculator/3.1)
- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [How to write a good report — Intigriti](https://blog.intigriti.com/hacking-tools/how-to-write-a-good-bug-bounty-report/)
