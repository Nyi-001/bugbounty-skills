# Skill Template

> Copy this file, rename it (e.g. `graphql-deep-dive.md`), fill in every section, and drop it in `recon/` or `vulnerabilities/`. Delete this tip block when done.

# <Vulnerability Name>

> One-line summary: what the vuln is + why it pays in bug bounty.

## Overview

What it is, how the flaw arises, typical impact. 3-5 sentences.

## Where to find it

- Attack surface bullet: input points, endpoints, features, frameworks
- Which roles/contexts are affected

## Methodology

Numbered steps, concrete workflow:

1. **Find candidates** — where and how to look
2. **Test** — exact requests/params to try, variations to cover
3. **Confirm** — how to tell a true positive from a false positive, without causing damage
4. **Prove impact** — the evidence that makes it a paid report

## Payloads

```bash
# Real, working payloads and commands (target.com as example domain)
```

## Bypasses & edge cases

WAF/filter bypasses, framework quirks, unusual contexts.

## Tools

- `toolname` — what it does
- Copy-pasteable commands

## Escalation & chaining

How to raise impact by combining with other vuln classes.

## Report notes

What a paid report needs: exact payloads, raw requests, screenshots, timing evidence.

## References

- [PortSwigger Academy](https://portswigger.net/web-security)
- [OWASP](https://owasp.org/)
- [HackTricks](https://book.hacktricks.xyz/)
- 2-3 reputable writeups
