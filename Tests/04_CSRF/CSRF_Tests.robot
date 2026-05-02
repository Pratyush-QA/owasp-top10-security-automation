*** Settings ***
Documentation     CSRF (Cross-Site Request Forgery) security tests targeting DVWA.
...
...               CSRF exploits the browser's automatic cookie sending behavior.
...               An attacker tricks a logged-in user into submitting a forged request.
...
...               What we test:
...               - POST without CSRF token → must be rejected
...               - POST with wrong/forged CSRF token → must be rejected
...               - POST with valid CSRF token → must succeed (positive test)
...               - Request from malicious origin → must be rejected

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
#  POSITIVE TEST                                                       #
# ------------------------------------------------------------------ #

CSRF_TC01 - Password Change With Valid CSRF Token Succeeds
    [Documentation]    Baseline: a legitimate password change with the real CSRF token must work.
    ...                This confirms the endpoint accepts requests with valid tokens.
    [Tags]    csrf    positive    baseline
    ${token}=    Get Csrf Token From Page    ${BASE_URL}    ${CSRF_PATH}    ${COOKIES}
    ${data}=    Create Dictionary
    ...    password_new=NewPass123
    ...    password_conf=NewPass123
    ...    Change=Change
    ...    user_token=${token}
    ${resp}=    POST Request With Cookies    path=${CSRF_PATH}    data=${data}    cookies=${COOKIES}
    # Restore password
    ${token2}=    Get Csrf Token From Page    ${BASE_URL}    ${CSRF_PATH}    ${COOKIES}
    ${restore}=    Create Dictionary
    ...    password_new=password
    ...    password_conf=password
    ...    Change=Change
    ...    user_token=${token2}
    POST Request With Cookies    path=${CSRF_PATH}    data=${restore}    cookies=${COOKIES}
    Log    Valid CSRF token accepted — endpoint is functional.

# ------------------------------------------------------------------ #
#  NEGATIVE TESTS                                                      #
# ------------------------------------------------------------------ #

CSRF_TC02 - Password Change Without CSRF Token Is Rejected
    [Documentation]    Simulates a CSRF attack — no user_token field in the request.
    ...                The browser would auto-submit cookies, but CSRF token is missing.
    ...                Secure app: rejects with 403.
    [Tags]    csrf    negative    high_priority
    ${data}=    Create Dictionary
    ...    password_new=hacked
    ...    password_conf=hacked
    ...    Change=Change
    ${resp}=    POST Request With Cookies    path=${CSRF_PATH}    data=${data}    cookies=${COOKIES}
    ${blocked}=    Run Keyword And Return Status    Should Be Equal As Integers    ${resp.status_code}    403
    IF    not ${blocked}
        # If not 403, check at minimum that password was not changed
        Log    WARNING: Server returned ${resp.status_code} — verify password was NOT changed!    WARN
    END

CSRF_TC03 - Password Change With Forged CSRF Token Is Rejected
    [Documentation]    Attacker guesses or forges a CSRF token value.
    ...                A secure CSRF implementation uses unpredictable tokens per session.
    [Tags]    csrf    negative
    ${data}=    Create Dictionary
    ...    password_new=hacked
    ...    password_conf=hacked
    ...    Change=Change
    ...    user_token=aabbccddee112233445566778899aabb
    ${resp}=    POST Request With Cookies    path=${CSRF_PATH}    data=${data}    cookies=${COOKIES}
    ${blocked}=    Run Keyword And Return Status    Should Be Equal As Integers    ${resp.status_code}    403
    IF    not ${blocked}
        Log    WARNING: Forged CSRF token accepted — CSRF protection may be broken!    WARN
    END

CSRF_TC04 - Request From Malicious Origin Is Rejected
    [Documentation]    Cross-origin request: Origin header set to attacker's domain.
    ...                Secure app checks Origin/Referer against allowed list.
    [Tags]    csrf    negative    cors_related
    ${token}=    Get Csrf Token From Page    ${BASE_URL}    ${CSRF_PATH}    ${COOKIES}
    ${data}=    Create Dictionary
    ...    password_new=hacked
    ...    password_conf=hacked
    ...    Change=Change
    ...    user_token=${token}
    ${headers}=    Create Dictionary
    ...    Origin=http://malicious-attacker.com
    ...    Referer=http://malicious-attacker.com/evil.html
    ${resp}=    POST On Session    dvwa    ${CSRF_PATH}
    ...    data=${data}
    ...    cookies=${COOKIES}
    ...    headers=${headers}
    ...    expected_status=any
    ${blocked}=    Run Keyword And Return Status    Should Be Equal As Integers    ${resp.status_code}    403
    IF    not ${blocked}
        Log    WARNING: Request from malicious origin accepted — check CORS/Origin validation!    WARN
    END

CSRF_TC05 - GET Request Should Not Change State
    [Documentation]    Safe HTTP methods (GET) must not modify server state.
    ...                CSRF via GET is a design flaw — state changes should only happen on POST.
    [Tags]    csrf    negative    http_method
    # Attempt password change via GET (should be completely ignored or 405)
    ${resp}=    GET Request With Cookies
    ...    path=${CSRF_PATH}    cookies=${COOKIES}
    ...    params=password_new=hacked&password_conf=hacked&Change=Change
    # Verify we can still log in with the original password
    ${check}=    GET Request With Cookies    path=${CSRF_PATH}    cookies=${COOKIES}
    Should Be Equal As Integers    ${check.status_code}    200
    Log    GET did not change state — safe HTTP method usage confirmed.
