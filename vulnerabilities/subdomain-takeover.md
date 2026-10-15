# Subdomain Takeover

> One-line summary: A dangling DNS record points at a deprovisioned third-party resource (GitHub Pages, Heroku, S3, …) that anyone can re-register — letting you serve content on the target's own domain and inherit its trust (cookies, OAuth, CSP, SSO).

## Overview

Subdomain takeover happens when DNS still points to a resource that no longer exists — a CNAME to a deleted Heroku app, GitHub Pages site, or S3 bucket — and the provider lets a new user claim that exact name. The attacker re-registers the name and instantly controls a host under the target's domain, with a valid TLS certificate. Impact is trust inheritance: parent-domain cookies (`.target.com`) are readable/settable from the taken-over host, OAuth `redirect_uri` allowlists with wildcards accept it, `script-src *.target.com` CSPs load scripts from it, SSO trusts it, and MX records can receive email. Most programs rate standalone takeovers medium and chained ones (auth bypass, cookie theft, token capture) high/critical — prove the chain, not just the claim.

## Where to find it

- Any subdomain whose CNAME points at a SaaS/platform: landing pages, status pages, docs, help centers, abandoned product pages, demo environments, old campaign sites.
- Record types to check: CNAME (main case), A to released cloud IPs (Elastic IP takeover), NS delegation (highest impact), MX (email capture), TXT (domain-verification/`_acme-challenge` reclaims).
- Services commonly seen in the wild: GitHub Pages, Heroku, AWS S3/CloudFront, Azure (`azurewebsites.net`, `trafficmanager.net`, `azurefd.net`, `cloudapp.azure.com`), Fastly, Netlify, Vercel, Firebase, Read the Docs, WordPress.com, Shopify, Zendesk, Statuspage, Ghost, Surge.sh, Bitbucket, Pantheon, Tumblr, UserVoice, HelpScout, Desk, FeedPress, Pingdom, Teamwork, Cargo, Strikingly.
- Also test subdomains that resolve to a service error page but return 403/404 — CloudFront unknown-domain responses are a classic.

## Methodology

1. **Enumerate.** `subfinder -d target.com -all -silent -o subs.txt`, add `assetfinder`, crt.sh CT logs, amass passive, and brute-force if allowed. Dedupe. Include subdomains of subdomains.
2. **Resolve and filter to third-party targets.** `dnsx -l subs.txt -cname -resp -silent -o cnames.txt` and `dig +short CNAME old.target.com`. Grep CNAMEs against the known-service list (can-i-take-over-xyz). Also flag NXDOMAIN CNAME targets — the service itself is gone, which is even easier to claim if you can register that domain.
3. **Fingerprint unclaimed status.** Request the host and match the body/headers against provider error fingerprints (Payloads). Confirm against **can-i-take-over-xyz** — it tracks vulnerable / not-vulnerable / edge-case per provider, and lists change as providers add verification.
4. **Verify claimability before claiming destructively.** Check the name is actually free on the provider: GitHub Pages user/org name, Heroku app name, S3 bucket name (global namespace), Azure app name. Do **not** try to claim names that belong to live production apps — prove the resource is deleted (error page + NXDOMAIN upstream), not merely misconfigured.
5. **Claim with a benign proof.** Register the free-tier resource and publish a static page (or a hidden file) proving control: your handle in an HTML comment at `/h1-proof-<handle>.txt`. Never deface or serve anything malicious. Screenshot the live URL with the address bar visible.
6. **Prove trust inheritance (the impact).** Show what the domain gets you: read a `.target.com` cookie (`document.cookie` after the main app sets one), or that the OAuth flow accepts this host as `redirect_uri`. If the program forbids active testing beyond the claim, describe the chain and ask for explicit permission in the report.
7. **Report fast, then cooperate.** The claim is live and anyone can see the dangling record; submit immediately, keep content benign, and remove it after triage if asked. State that in the report.

## Payloads

```text
# Fingerprints for common vulnerable services (verify against can-i-take-over-xyz — this list rots)
github.io             → "There isn't a GitHub Pages site here."        (404 on the bare <user>.github.io name)
herokuapp.com         → "No such app"                                   (herokucdn.com/error-pages/no-such-app.html)
s3.amazonaws.com      → "NoSuchBucket" / "The specified bucket does not exist"
cloudfront.net        → "Bad request. ERROR: The request could not be satisfied." (403; distribution deleted, alias unclaimed)
azurewebsites.net     → 404 "Error 404 - Web app not found." / "This web app is stopped."
trafficmanager.net    → Azure "not found" page for a deleted traffic manager profile
azurefd.net / cloudapp.azure.com → Azure dangling-resource error pages
blob.core.windows.net → "The requested URI does not represent any resource on the server."
readthedocs.io        → "404 - unknown domain"
wordpress.com         → "Do you want to register <name>.wordpress.com?"
surge.sh              → "project not found"
bitbucket.io          → "Repository not found"
ghost.io              → "Domain error" / "Site not found"
zendesk.com           → "Help Center Closed" / "Oops, this help center no longer exists"
shopify.com           → "Sorry, this shop is currently unavailable."
fastly.net            → "Fastly error: unknown domain: <host>." (claimable when the domain is not attached to any service)
pantheonsite.io       → "The gods are wise, but do not know of the site which you seek."
webflow.io            → "The page you are looking for doesn't exist or has been moved."
tumblr.com            → "Whatever you were looking for doesn't currently exist at this address."
uservoice.com         → "This UserVoice subdomain is currently available!"
helpscoutdocs.com     → "No settings were found for this company:"
desk.com              → "This desk is temporarily out of service."
feedpress.me          → "The feed has not been found."
pingdom.com           → "Sorry, couldn't find the status page"
teamwork.com          → "Oops - We didn't find your site."
cargo.site            → 404 Not Found (custom domain not attached)
strikingly.com        → "isn't a working website yet"
firebaseapp.com       → "Site Not Found"
vercel.app / now.sh   → "The deployment could not be found on Vercel." (DEPLOYMENT_NOT_FOUND; free tier can take an unused project name)
elasticbeanstalk.com  → NXDOMAIN or ELB 404 for a deleted environment (claim by creating an environment with the same name)
netlify.app           → "Not Found - Request ID:" (domain verification may block claim)
statuspage.io         → statuspage "Page not found" (verify current status on can-i-take-over-xyz)
```

```bash
# 1. Enumerate
subfinder -d target.com -all -silent -o subs.txt
assetfinder --subs-only target.com | sort -u >> subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u >> subs.txt
amass enum -passive -d target.com -o amass.txt

# 2. Resolve CNAMEs and live hosts
dig +short CNAME old.target.com
dnsx -l subs.txt -cname -resp -silent -o cnames.txt
httpx-toolkit -l subs.txt -silent -status-code -title -td -location -o httpx.txt   # projectdiscovery httpx on non-Kali

# 2b. Other record types (NS delegation, mail, verification TXT)
dig +short NS sub.target.com
dig +short MX target.com
dig +short TXT _github-pages-challenge.target.com

# 2c. Typical dangling-record evidence
dig +short old.target.com                       # -> old.herokudns.com.
curl -s https://old.target.com | grep -o "No such app"   # -> No such app

# 3. Automated checks (nuclei: 74 takeover templates at http/takeovers/; dns templates for dangling records)
nuclei -l subs.txt -t http/takeovers/ -o takeovers.txt
nuclei -l subs.txt -t dns/ -o dns-findings.txt      # includes detect-dangling-cname, azure/elasticbeanstalk takeover
subzy run --targets subs.txt

# 4. Claim proof example (S3 bucket)
aws s3 mb s3://dangling-bucket-name
aws s3 cp proof.html s3://dangling-bucket-name/index.html --acl public-read
curl -s https://old.target.com/ | head

# 5. Cookie scope check from the taken-over host: has the main app set a .target.com cookie?
#    In the browser console on https://old.target.com/ :
document.cookie
```

```html
<!-- proof.html — benign, no defacement, no scripts beyond a marker -->
<html><body>
proof-of-control: <your-handle> — see /h1-proof-<handle>.txt
<!-- <your-handle> claimed this dangling resource during an authorized test -->
</body></html>
```

## Bypasses & edge cases

- **Wildcard CNAMEs:** `dig +short CNAME random123.target.com` — if the wildcard points at a service, each name may be individually claimable; brute-force names against it.
- **CNAME to a dead service domain (NXDOMAIN):** the SaaS company itself vanished — registering that domain takes over *every* customer at once. Highest blast radius; check before assuming the record is dead.
- **Elastic IP / A-record takeover:** a released EC2 Elastic IP or Azure public IP still referenced by an A record can be allocated and reused; requires cloud account + the IP being free in that region.
- **NS delegation takeover:** `dig NS sub.target.com` pointing at nameservers under a domain you can register → full DNS control for the subtree (any record you want). Rare, critical.
- **MX takeover:** `dig MX target.com` pointing at `mx.sendgrid.net` / `mx.mailgun.org` without the domain being verified in the provider's inbound-parse/webhook feature → claim the domain in your provider account and receive password-reset email, including 2FA codes.
- **TXT verification records:** dangling service-verification TXT records can let you (re-)verify a domain on a platform as if you were the owner.
- **Providers that added protection:** GitHub Pages custom-domain verification, Netlify's domain verification, CloudFront's alias/X.509 requirements — these are the "edge case" rows on can-i-take-over-xyz. Confirm current behavior before reporting; a 404 page alone is not proof of claimability.
- **Partial control:** some services let you claim the name but inject a new TLS/verification requirement first (serving HTTP but not HTTPS, or vice versa) — note exactly what you control in the report.
- **Subdomain of a subdomain:** `old.dev.target.com` with its own dangling CNAME is in scope for the same bug; enumeration depth matters.
- **Automation false positives:** scanners flag every 404 — a 404 page alone is not a takeover. Confirm the provider actually allows claiming that exact name (user/org, app, bucket, project) before reporting.
- **Historical confirmation:** the Wayback Machine or urlscan showing the host was once live on that service is good evidence the resource is abandoned rather than intentionally parked.
- **Wildcard TLS:** check `crt.sh` history for certs issued to the host — a live or previously issued `*.target.com` cert means your claimed host serves trusted HTTPS immediately, which is what makes cookie/OAuth chains work.
- **Scope discipline:** the dangling CNAME may point at a third party's domain that is out of scope — test only the in-scope host, keep the claim minimal.

## Tools

- **subfinder / assetfinder / amass / findomain** — passive subdomain enumeration; combine outputs with crt.sh and CT-log-derived lists.
- **dnsx / dig** — CNAME, A, NS, MX resolution: `dnsx -l subs.txt -cname -mx -ns -resp -o records.txt`
- **httpx (Kali: httpx-toolkit)** — reachable-host triage with titles and tech detection: `httpx-toolkit -l subs.txt -sc -title -td -o httpx.txt`
- **nuclei** — `nuclei -l subs.txt -t http/takeovers/` plus the DNS templates `dns/detect-dangling-cname.yaml`, `dns/azure-takeover-detection.yaml`, `dns/elasticbeanstalk-takeover.yaml`
- **subzy** — quick takeover sweep: `subzy run --targets subs.txt`
- **subjack / tko-subs** — older fingerprint scanners; useful as a second opinion with a different fingerprint database.
- **can-i-take-over-xyz** — the authoritative service/status/fingerprint table; check it before every report.
- **Cloud CLIs** (`aws`, `az`) — for claiming S3 buckets, CloudFront aliases, Azure app names when proving a takeover.

## Escalation & chaining

- **Cookie theft / session fixation:** if the main app sets `Domain=.target.com` cookies, the taken-over host can read non-HttpOnly ones and *write* cookies for the whole parent domain — session fixation or direct session theft if `HttpOnly` is missing.
- **OAuth `redirect_uri` wildcard:** providers that allow `https://*.target.com/callback` will hand the victim's `code`/`token` to your host → account takeover on the main app.
- **SSO/SAML metadata trust:** if the IdP trusts the subdomain (ACS URL, SP metadata), you can receive assertions meant for the app.
- **CSP bypass:** `script-src` allowing `*.target.com` (or the specific subdomain) means you host the JS → XSS on the main application that no CSP stops.
- **CORS trust:** APIs reflecting `Origin: https://*.target.com` with credentials → read authenticated API responses from the taken-over origin.
- **Email:** MX takeover receives password-reset and 2FA mail; SPF/DKIM records under the subdomain enable mail spoofing.
- **Chained to the app itself:** if the app fetches the subdomain server-side (widgets, previews, webhooks), a takeover can pivot into SSRF or stored XSS against the main app.
- **Trusted-sender email:** if the dangling record is a sending subdomain (SendGrid, Mailgun, Customer.io, SparkPost), claiming it can let you send authenticated mail as the brand — DKIM/SPF alignment makes it pass filters.
- **Phishing on the trusted domain** — a real but low-rated standalone use; include it only as an additional impact bullet, not the main claim.

## Report notes

- DNS evidence: full `dig` output for the CNAME chain (and A/NS/MX if relevant) plus the provider error page screenshot/body proving the resource is unclaimed.
- Proof of control: live URL screenshot with the address bar showing `https://old.target.com/...` and your benign file, with a timestamp — the file path containing your handle is the standard, non-destructive PoC.
- Impact chain, concretely: the exact cookie scope observed (`Set-Cookie: ... Domain=.target.com`), or the OAuth authorize URL that accepted the subdomain as `redirect_uri`, or the CSP header containing the wildcard.
- State clearly that you claimed the name, that the content is benign, and that you will release the claim on request — programs treat unclaimed dangling names as race conditions and want fast triage.
- Remediation one-liner: delete the dangling DNS record (or re-claim the resource); where supported, enable the provider's domain-verification feature for the future.
- If you found it via automation, say so and show the fingerprint match — it helps triage trust the claimability assessment.

## References

- [EdOverflow — can-i-take-over-xyz (fingerprints and provider status)](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Detectify Labs — Hostile subdomain takeover using Heroku/GitHub/Desk and more](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)
- [HackerOne — A Guide To Subdomain Takeovers 2.0](https://www.hackerone.com/blog/guide-subdomain-takeovers-20)
- [HackTricks — Domain/Subdomain takeover](https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover)
- [HackerOne #172137 — Ubiquiti: subdomain takeover of ping.ubnt.com chained to SSO session theft](https://hackerone.com/reports/172137)
- [HackerOne #219205 — Uber: takeover of saostatic.uber.com leading to authentication bypass](https://hackerone.com/reports/219205)
- [HackerOne #335330 — Roblox: subdomain takeover leading to auth bypass](https://hackerone.com/reports/335330)
- [HackerOne #1717626 — MetaMask/ConsenSys: subdomain takeover via unclaimed Squarespace domain](https://hackerone.com/reports/1717626)
