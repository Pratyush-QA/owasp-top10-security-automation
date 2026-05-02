*** Settings ***
Library    RequestsLibrary
Library    Collections
Library    String
Library    OperatingSystem
Library    ../Libraries/SecurityUtils.py
Resource   Variables.robot

*** Keywords ***
# ------------------------------------------------------------------ #
#  Setup / Teardown                                                    #
# ------------------------------------------------------------------ #
Get Authenticated Session
    [Documentation]    Log into DVWA and return a cookie dict for use in requests.
    ${cookies}=    Authenticate And Get Session    ${BASE_URL}
    RETURN    ${cookies}

Create Session For DVWA
    [Documentation]    Create a RequestsLibrary session for DVWA.
    Create Session    dvwa    ${BASE_URL}    verify=False

# ------------------------------------------------------------------ #
#  HTTP helpers                                                        #
# ------------------------------------------------------------------ #
GET Request With Cookies
    [Arguments]    ${path}    ${cookies}    ${params}=${EMPTY}
    ${resp}=    GET On Session    dvwa    ${path}    params=${params}    cookies=${cookies}
    RETURN    ${resp}

POST Request With Cookies
    [Arguments]    ${path}    ${data}    ${cookies}
    ${resp}=    POST On Session    dvwa    ${path}    data=${data}    cookies=${cookies}
    RETURN    ${resp}

# ------------------------------------------------------------------ #
#  Assertion helpers                                                   #
# ------------------------------------------------------------------ #
Response Should Be Blocked
    [Arguments]    ${resp}    ${expected_codes}=400,403,422,500
    ${codes}=    Split String    ${expected_codes}    ,
    ${actual}=    Convert To String    ${resp.status_code}
    Should Contain    ${expected_codes}    ${actual}
    ...    msg=Expected a blocking response code (${expected_codes}) but got ${resp.status_code}

Response Should Not Expose System Files
    [Arguments]    ${resp}
    Response Should Not Expose System Data    ${resp.text}

Response Should Not Expose DB Content
    [Arguments]    ${resp}
    Response Should Not Expose Db Data    ${resp.text}

XSS Payload Should Be Sanitized In Response
    [Arguments]    ${resp}    ${payload}
    Should Not Contain    ${resp.text}    ${payload}
    ...    msg=Unsanitized XSS payload found in response — vulnerability confirmed!

Response Should Not Contain Script Tags
    [Arguments]    ${resp}
    Should Not Contain    ${resp.text}    <script>
    Should Not Contain    ${resp.text}    onerror=
    Should Not Contain    ${resp.text}    onload=

Status Code Should Be 200
    [Arguments]    ${resp}
    Should Be Equal As Integers    ${resp.status_code}    200

Status Code Should Be 401
    [Arguments]    ${resp}
    Should Be Equal As Integers    ${resp.status_code}    401
    ...    msg=Expected 401 Unauthorized but got ${resp.status_code}

Status Code Should Be 403
    [Arguments]    ${resp}
    Should Be Equal As Integers    ${resp.status_code}    403
    ...    msg=Expected 403 Forbidden but got ${resp.status_code}
