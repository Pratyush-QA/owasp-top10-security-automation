# Security Testing Portfolio

Automated web application security tests built with **Robot Framework**.

Demonstrates practical security testing as an SDET — covering OWASP Top 10 vulnerabilities
using a real target app (DVWA) with clear, readable test cases.

---

## Test Suites

| # | Suite | Tests | Techniques |
|---|-------|-------|-----------|
| 01 | SQL Injection | 12 | Tautology, UNION, Time-based Blind, DDL, Header injection |
| 02 | Cross-Site Scripting | 11 | Reflected, Stored, Event handlers, Encoding bypasses |
| 03 | JWT / Token Security | 13 | alg:none, Payload tamper, Rogue issuer, Boundary cases |
| 04 | CSRF | 5 | Missing token, Forged token, Malicious origin |
| 05 | File Upload | 7 | Webshell, MIME bypass, Double extension, Magic bytes |
| 06 | Command Injection | 10 | ;, &&, \|, \|\|, Time-based, Input validation |
| 07 | File Inclusion | 12 | LFI, RFI, Encoding bypasses, PHP wrappers, Null byte |

**Total: 70 test cases across 7 vulnerability categories**

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Start DVWA (target app)
```bash
docker-compose up -d
```
Wait ~30 seconds for DVWA to initialize, then open http://localhost:4280

First-time setup in browser: click **"Create / Reset Database"** on the setup page.

> Default credentials: `admin` / `password`

### 3. Start JWT Demo Server (for JWT tests only)
```bash
python jwt_demo_server.py
```
Runs at http://localhost:5050

### 4. Run tests

**All suites:**
```bash
robot --outputdir results Tests/
```

**Single suite:**
```bash
robot --outputdir results Tests/01_SQL_Injection/
robot --outputdir results Tests/02_XSS/
robot --outputdir results Tests/03_JWT_Security/
robot --outputdir results Tests/04_CSRF/
robot --outputdir results Tests/05_File_Upload/
robot --outputdir results Tests/06_Command_Injection/
robot --outputdir results Tests/07_File_Inclusion/
```

**By tag:**
```bash
robot --include high_priority --outputdir results Tests/
robot --include critical --outputdir results Tests/
```

---

## Project Structure

```
owasp-top10-security-automation/
├── Tests/
│   ├── 01_SQL_Injection/       SQLInjection_Tests.robot
│   ├── 02_XSS/                 XSS_Tests.robot
│   ├── 03_JWT_Security/        JWT_Security_Tests.robot
│   ├── 04_CSRF/                CSRF_Tests.robot
│   ├── 05_File_Upload/         FileUpload_Tests.robot
│   ├── 06_Command_Injection/   CommandInjection_Tests.robot
│   └── 07_File_Inclusion/      FileInclusion_Tests.robot
├── Resources/
│   ├── CommonKeywords.robot    Shared keywords and assertions
│   └── Variables.robot         Base URL, paths, payloads
├── Libraries/
│   └── SecurityUtils.py        JWT manipulation, file creation, response validation
├── jwt_demo_server.py          Local Flask server for JWT tests
├── docker-compose.yml          Spins up DVWA
└── requirements.txt
```

---

## How Tests Are Structured

Each test suite follows the same pattern:

```
1. Positive test  → confirms the endpoint works normally (baseline)
2. Negative tests → inject attack payloads, verify they are blocked
3. Boundary tests → edge cases (empty input, very long strings, encoding)
```

Each test includes:
- `[Documentation]` — what the attack is and what the test validates
- `[Tags]` — category tags for selective running
- Clear assertion messages — explains WHAT failed if a test fails

---

## OWASP Top 10 Mapping

| OWASP | Category | Covered By |
|-------|----------|-----------|
| A01 — Broken Access Control | IDOR, privilege escalation | JWT_TC05, JWT_TC06 |
| A03 — Injection | SQL, Command, LFI | Suites 01, 06, 07 |
| A04 — Insecure Design | No CSRF token validation | Suite 04 |
| A07 — Authentication Failures | JWT attacks | Suite 03 |
| A08 — Software Integrity Failures | JWT tampering, CSRF | Suites 03, 04 |
| A10 — SSRF / Path Traversal | File inclusion | Suite 07 |

---

## About

Built as a portfolio project to demonstrate **security testing automation skills** as an SDET.

Target app: [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) —
an intentionally vulnerable PHP/MySQL web app designed for security training.

> **Disclaimer:** These tests are for educational and authorized testing purposes only.
> Run ONLY against DVWA or systems you have explicit permission to test.
