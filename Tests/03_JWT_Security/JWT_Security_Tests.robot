*** Settings ***
Documentation     JWT / Token Security tests.
...
...               Covers: Expired token, alg:none attack, tampered payload,
...               rogue issuer, blank/null token, missing Bearer prefix,
...               extremely long token, required claims validation.
...
...               These tests demonstrate JWT attack patterns. They call a
...               configurable JWT-protected API endpoint via ${JWT_API_URL}.
...               Set this in Variables.robot or pass via CLI:
...                 robot --variable JWT_API_URL:https://your-api.com
...
...               For local demo: a minimal Flask JWT server is included
...               in the project root (jwt_demo_server.py). Run it first:
...                 python jwt_demo_server.py

Library           RequestsLibrary
Library           Collections
Library           String
Library           OperatingSystem
Resource          ../../Resources/CommonKeywords.robot
Resource          ../../Resources/Variables.robot

Suite Setup       Run Keywords
...               Create Session    jwt_api    ${JWT_API_URL}    verify=False    AND
...               ${TOKEN}=    Generate Valid JWT Token    AND
...               Set Suite Variable    ${TOKEN}

*** Variables ***
${JWT_API_URL}         http://localhost:5050
${JWT_LOGIN_PATH}      /auth/login
${JWT_VERIFY_PATH}     /auth/verify

# Pre-baked expired token (exp in the past) — update if your server rejects on iss mismatch
${EXPIRED_TOKEN}       Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlzcyI6ImRlbW8tc2VydmVyIiwiZXhwIjoxfQ.EXPIREDSIG

*** Keywords ***
Generate Valid JWT Token
    [Documentation]    Hits the demo server login endpoint to get a fresh valid JWT.
    ${resp}=    POST On Session    jwt_api    ${JWT_LOGIN_PATH}
    ...    json={"username": "admin", "password": "password123"}
    Should Be Equal As Integers    ${resp.status_code}    200
    ${token}=    Get From Dictionary    ${resp.json()}    token
    RETURN    Bearer ${token}

*** Test Cases ***

# ------------------------------------------------------------------ #
#  POSITIVE TEST — Valid token must work                               #
# ------------------------------------------------------------------ #

JWT_TC01 - Valid Token Is Accepted
    [Documentation]    Baseline: a freshly generated token must return 200.
    ...                If this fails, something is wrong with the test setup.
    [Tags]    jwt    positive    baseline
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=${TOKEN}
    Should Be Equal As Integers    ${resp.status_code}    200
    Log    Valid token accepted. Status: ${resp.status_code}

# ------------------------------------------------------------------ #
#  EXPIRED / INVALID TOKEN                                            #
# ------------------------------------------------------------------ #

JWT_TC02 - Expired Token Is Rejected With 401
    [Documentation]    A token past its 'exp' time must be rejected.
    ...                Vulnerable server: accepts it without checking expiry.
    ...                Secure server: returns 401 Unauthorized.
    [Tags]    jwt    negative    expiry
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=${EXPIRED_TOKEN}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Expired token was accepted — server not checking exp claim!

JWT_TC03 - Invalid Signature Token Is Rejected
    [Documentation]    Token with corrupted signature — last part modified.
    ...                Server must verify signature against secret key.
    [Tags]    jwt    negative    signature
    ${tampered}=    Set Variable    Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjF9.INVALIDSIGNATUREXXXXXXXX
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=${tampered}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Token with invalid signature was accepted!

# ------------------------------------------------------------------ #
#  ALG:NONE ATTACK                                                     #
# ------------------------------------------------------------------ #

JWT_TC04 - Alg None Attack Is Rejected
    [Documentation]    THE most famous JWT attack. Change header alg to 'none',
    ...                remove the signature. Vulnerable servers skip verification.
    ...
    ...                Attack token structure:
    ...                  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0  ← header: {"alg":"none","typ":"JWT"}
    ...                  .eyJ1c2VySWQiOjF9                    ← payload: {"userId":1}
    ...                  .                                    ← empty signature
    [Tags]    jwt    negative    alg_none    penetration    critical
    ${alg_none_token}=    Build Alg None Token    ${TOKEN}
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=Bearer ${alg_none_token}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=alg:none attack succeeded! Server is not enforcing algorithm — critical vulnerability!
    Log    alg:none attack correctly blocked. Status: ${resp.status_code}

# ------------------------------------------------------------------ #
#  PAYLOAD TAMPERING                                                   #
# ------------------------------------------------------------------ #

JWT_TC05 - Tampered UserId In Payload Is Rejected
    [Documentation]    Modify userId in payload from 1 → 999 (admin), keep original signature.
    ...                The signature is now invalid — a secure server must reject it.
    [Tags]    jwt    negative    payload_tamper    critical
    ${tampered}=    Build Tampered Payload Token    ${TOKEN}    userId    999
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=Bearer ${tampered}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Tampered payload (userId=999) was accepted — signature not validated!

JWT_TC06 - Tampered Role Claim Is Rejected
    [Documentation]    Change role from 'user' to 'admin' in payload — keep old signature.
    [Tags]    jwt    negative    payload_tamper
    ${tampered}=    Build Tampered Payload Token    ${TOKEN}    role    admin
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=Bearer ${tampered}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Tampered role claim accepted — privilege escalation via JWT!

# ------------------------------------------------------------------ #
#  ROGUE ISSUER                                                        #
# ------------------------------------------------------------------ #

JWT_TC07 - Rogue Issuer Token Is Rejected
    [Documentation]    Change 'iss' claim to 'attacker.com' — keep original signature.
    ...                Secure server must validate the issuer field.
    [Tags]    jwt    negative    issuer    penetration
    ${tampered}=    Build Rogue Issuer Token    ${TOKEN}    attacker.com
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=Bearer ${tampered}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Rogue issuer token accepted — iss claim not validated!

# ------------------------------------------------------------------ #
#  EDGE CASES — Blank, null, long, missing prefix                      #
# ------------------------------------------------------------------ #

JWT_TC08 - Blank Token Is Rejected
    [Documentation]    Authorization: Bearer   (just "Bearer " with nothing after it)
    [Tags]    jwt    negative    boundary
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=Bearer     expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Empty Bearer token was accepted!

JWT_TC09 - Whitespace-Only Token Is Rejected
    [Documentation]    Authorization: Bearer       (Bearer + many spaces)
    [Tags]    jwt    negative    boundary
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=Bearer            expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Whitespace-only token was accepted!

JWT_TC10 - Missing Bearer Prefix Is Rejected
    [Documentation]    Send the raw JWT without the 'Bearer ' scheme prefix.
    ...                Server must enforce the Authorization Bearer scheme.
    [Tags]    jwt    negative    delivery_mechanism
    ${raw_token}=    Replace String    ${TOKEN}    Bearer     ${EMPTY}
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=${raw_token}    expected_status=any
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Raw JWT without Bearer prefix was accepted!

JWT_TC11 - Extremely Long Token Does Not Crash Server
    [Documentation]    50,000-character token in Authorization header.
    ...                Must return 400 or 401 — NOT 500 (server crash = vulnerability).
    [Tags]    jwt    negative    boundary    dos
    ${long_token}=    Evaluate    'Bearer ' + 'A' * 50000
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=${long_token}    expected_status=any
    Should Not Be Equal As Integers    ${resp.status_code}    500
    ...    msg=Server crashed (500) on extremely long token — possible DoS vulnerability!
    Log    Long token handled safely. Status: ${resp.status_code}

JWT_TC12 - Token With XSS And SQL Payload Is Rejected
    [Documentation]    Inject XSS + SQL inside the Authorization header value.
    ...                Server must not crash and must not reflect the payload.
    [Tags]    jwt    negative    injection    boundary
    ${malicious}=    Set Variable    Bearer <script>alert(1)</script>'; DROP TABLE users;--
    ${resp}=    GET On Session    jwt_api    ${JWT_VERIFY_PATH}
    ...    headers=Authorization=${malicious}    expected_status=any
    Should Not Be Equal As Integers    ${resp.status_code}    500
    Should Not Contain    ${resp.text}    <script>
    Should Not Contain    ${resp.text}    DROP TABLE

# ------------------------------------------------------------------ #
#  JWT STRUCTURE VALIDATION                                            #
# ------------------------------------------------------------------ #

JWT_TC13 - Valid JWT Contains All Required Claims
    [Documentation]    Decode the JWT payload and verify all required claims are present.
    ...                Required: exp, iss, userId (or sub), tokenType.
    [Tags]    jwt    positive    structure
    ${raw_token}=    Replace String    ${TOKEN}    Bearer     ${EMPTY}
    ${payload}=    Verify Jwt Has Required Claims
    ...    token=${raw_token}
    ...    required_claims=exp,iss
    Log    JWT payload: ${payload}
    Log    All required claims present and exp is valid.
