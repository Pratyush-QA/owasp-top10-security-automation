*** Settings ***
Documentation     SQL Injection security tests targeting DVWA (Security Level: LOW).
...
...               Covers: Boolean/Tautology, UNION-based, Time-based Blind, DDL injection,
...               Header injection, and Admin bypass attacks.
...
...               Setup: docker-compose up -d  (see project README)
...               Target: http://localhost:4280/vulnerabilities/sqli/

Library           RequestsLibrary
Library           Collections
Library           String
Resource          ../../Resources/CommonKeywords.robot
Resource          ../../Resources/Variables.robot

Suite Setup       Run Keywords
...               Create Session For DVWA    AND
...               ${COOKIES}=    Get Authenticated Session    AND
...               Set Suite Variable    ${COOKIES}

*** Test Cases ***

# ------------------------------------------------------------------ #
#  TAUTOLOGY / BOOLEAN INJECTION                                       #
# ------------------------------------------------------------------ #

SQLI_TC01 - Boolean Tautology OR 1 equals 1 Is Blocked
    [Documentation]    Classic tautology: '  OR '1'='1 makes WHERE always true.
    ...                Secure app must return an error or single expected row — NOT all rows.
    [Tags]    sql_injection    tautology    high_priority
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=1' OR '1'='1&Submit=Submit
    Response Should Not Expose DB Content    ${resp}
    Log    Tautology blocked. Status: ${resp.status_code}

SQLI_TC02 - Boolean AND True Injection Is Blocked
    [Documentation]    ' AND 1=1 — always-true condition appended to existing query.
    [Tags]    sql_injection    tautology
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=1' AND 1=1 --&Submit=Submit
    Response Should Not Expose DB Content    ${resp}

SQLI_TC03 - Admin Bypass via Comment Injection Is Blocked
    [Documentation]    admin' -- comments out the password check in login queries.
    ...                Validates the API doesn't expose admin data on this bypass.
    [Tags]    sql_injection    bypass
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=admin' --&Submit=Submit
    Response Should Not Expose DB Content    ${resp}

# ------------------------------------------------------------------ #
#  UNION-BASED INJECTION                                              #
# ------------------------------------------------------------------ #

SQLI_TC04 - UNION SELECT Null Columns Is Blocked
    [Documentation]    First step of a UNION attack — probing how many columns the query returns.
    ...                Payload: ' UNION SELECT null, null -- (2 columns)
    [Tags]    sql_injection    union
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=' UNION SELECT null, null --&Submit=Submit
    Response Should Not Expose DB Content    ${resp}

SQLI_TC05 - UNION SELECT Current DB User Is Blocked
    [Documentation]    Extracts the current database user via UNION.
    ...                Payload: ' UNION SELECT null, user() --
    [Tags]    sql_injection    union    data_extraction
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=' UNION SELECT null, user() --&Submit=Submit
    Should Not Contain    ${resp.text}    @    msg=DB user (email format) leaked in response
    Log    UNION user() extraction blocked.

SQLI_TC06 - UNION SELECT Email and Password Extraction Is Blocked
    [Documentation]    Most dangerous UNION attack — extracts real user credentials.
    ...                Payload: ' UNION SELECT user, password FROM users --
    [Tags]    sql_injection    union    data_extraction    critical
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=' UNION SELECT user, password FROM users --&Submit=Submit
    Should Not Contain    ${resp.text}    admin
    ...    msg=Admin credentials may have been exposed via UNION injection!
    Response Should Not Expose DB Content    ${resp}

# ------------------------------------------------------------------ #
#  TIME-BASED BLIND INJECTION                                         #
# ------------------------------------------------------------------ #

SQLI_TC07 - Time-Based Blind SLEEP Injection Does Not Delay Response
    [Documentation]    Injects SLEEP(5) inside an IF condition.
    ...                If the app is vulnerable, response takes 5+ seconds.
    ...                This test FAILS if response time >= 4 seconds.
    [Tags]    sql_injection    blind    time_based
    ${start}=    Get Time    epoch
    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=1' OR IF(1=1, SLEEP(5), 0) --&Submit=Submit
    ${end}=    Get Time    epoch
    ${elapsed}=    Evaluate    ${end} - ${start}
    Response Time Should Be Less Than    ${elapsed}    ${MAX_RESPONSE_TIME_SEC}
    Log    Response time: ${elapsed}s — within safe threshold.

SQLI_TC08 - Time-Based Blind BENCHMARK Injection Does Not Delay Response
    [Documentation]    Alternative time-based payload using BENCHMARK() for DBs that block SLEEP.
    [Tags]    sql_injection    blind    time_based
    ${start}=    Get Time    epoch
    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=1' AND BENCHMARK(5000000, MD5(1)) --&Submit=Submit
    ${end}=    Get Time    epoch
    ${elapsed}=    Evaluate    ${end} - ${start}
    Response Time Should Be Less Than    ${elapsed}    ${MAX_RESPONSE_TIME_SEC}

# ------------------------------------------------------------------ #
#  DDL / DESTRUCTIVE INJECTION                                        #
# ------------------------------------------------------------------ #

SQLI_TC09 - DROP TABLE Injection Is Blocked
    [Documentation]    Attempts to inject a DDL command to destroy the users table.
    ...                Payload: '; DROP TABLE users; --
    ...                Secure apps use parameterized queries — DDL is never executed.
    [Tags]    sql_injection    ddl    destructive    critical
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id='; DROP TABLE users; --&Submit=Submit
    # Verify subsequent request still works — table should still exist
    ${verify_resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=1&Submit=Submit
    Should Be Equal As Integers    ${verify_resp.status_code}    200
    Log    DROP TABLE blocked — subsequent query still succeeds.

SQLI_TC10 - DELETE Statement Injection Is Blocked
    [Documentation]    Injects DELETE FROM to wipe table rows.
    [Tags]    sql_injection    ddl    destructive
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=1'; DELETE FROM users WHERE '1'='1'; --&Submit=Submit
    Response Should Not Expose DB Content    ${resp}

# ------------------------------------------------------------------ #
#  SPECIAL CHARACTERS & ENCODING BYPASSES                             #
# ------------------------------------------------------------------ #

SQLI_TC11 - SQL Comment Variants Are Blocked
    [Documentation]    Tests different SQL comment styles used to bypass filters:
    ...                -- (MySQL), # (MySQL), /* */ (standard)
    [Tags]    sql_injection    bypass
    FOR    ${comment}    IN    --    #    /**/
        ${resp}=    GET Request With Cookies
        ...    path=${SQLI_PATH}    cookies=${COOKIES}
        ...    params=id=1' OR '1'='1' ${comment}&Submit=Submit
        Response Should Not Expose DB Content    ${resp}
    END

SQLI_TC12 - SQL Injection via Numeric Parameter Is Blocked
    [Documentation]    Numeric parameters are also injectable if not parameterized.
    ...                Payload: 1 OR 1=1 (no quotes needed for numeric columns)
    [Tags]    sql_injection    numeric
    ${resp}=    GET Request With Cookies
    ...    path=${SQLI_PATH}    cookies=${COOKIES}
    ...    params=id=1 OR 1=1&Submit=Submit
    Response Should Not Expose DB Content    ${resp}
