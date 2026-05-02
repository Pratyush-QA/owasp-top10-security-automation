*** Settings ***
Documentation     Command Injection security tests targeting DVWA.
...
...               The DVWA /vulnerabilities/exec/ endpoint runs: ping -c 1 <USER_INPUT>
...
...               Attack operators tested:
...               ;   — run second command regardless of first
...               &&  — run second if first succeeds
...               |   — pipe first output to second
...               ||  — run second only if first fails
...               ``  — backtick command substitution
...               time-based — sleep to confirm without visible output
...
...               A secure endpoint must ONLY accept valid IP addresses.

Library           RequestsLibrary
Library           Collections
Library           String
Resource          ../../Resources/CommonKeywords.robot
Resource          ../../Resources/Variables.robot

Suite Setup       Run Keywords
...               Create Session For DVWA    AND
...               ${COOKIES}=    Get Authenticated Session    AND
...               Set Suite Variable    ${COOKIES}

*** Keywords ***
Execute Ping Command
    [Arguments]    ${ip_payload}
    [Documentation]    POST a payload to the DVWA command execution endpoint.
    ${data}=    Create Dictionary    ip=${ip_payload}    Submit=Submit
    ${resp}=    POST Request With Cookies    path=${COMMAND_EXEC_PATH}    data=${data}    cookies=${COOKIES}
    RETURN    ${resp}

*** Test Cases ***

# ------------------------------------------------------------------ #
#  POSITIVE TEST                                                       #
# ------------------------------------------------------------------ #

CMD_TC01 - Valid IP Address Ping Succeeds
    [Documentation]    Baseline: 127.0.0.1 should return ping output.
    ...                Confirms the endpoint is working and tests are set up correctly.
    [Tags]    command_injection    positive    baseline
    ${resp}=    Execute Ping Command    127.0.0.1
    Should Be Equal As Integers    ${resp.status_code}    200
    Should Contain Any    ${resp.text}    bytes from    ping    PING
    Log    Valid ping returned expected output.

# ------------------------------------------------------------------ #
#  SEMICOLON INJECTION                                                 #
# ------------------------------------------------------------------ #

CMD_TC02 - Semicolon Command Injection Is Blocked
    [Documentation]    ; runs the second command regardless of the first's exit code.
    ...                Payload: 127.0.0.1; cat /etc/passwd
    ...                Vulnerable: returns /etc/passwd contents.
    ...                Secure: returns only ping output or rejects entirely.
    [Tags]    command_injection    semicolon    high_priority
    ${resp}=    Execute Ping Command    127.0.0.1; cat /etc/passwd
    Response Should Not Expose System Files    ${resp}
    Log    Semicolon injection blocked.

CMD_TC03 - Semicolon whoami Injection Is Blocked
    [Documentation]    Payload: 127.0.0.1; whoami
    ...                Reveals the OS user the web server runs as.
    [Tags]    command_injection    semicolon
    ${resp}=    Execute Ping Command    127.0.0.1; whoami
    Should Not Contain    ${resp.text}    www-data
    Should Not Contain    ${resp.text}    root
    Should Not Contain    ${resp.text}    apache

# ------------------------------------------------------------------ #
#  AND / OR OPERATORS                                                  #
# ------------------------------------------------------------------ #

CMD_TC04 - AND Operator Injection Is Blocked
    [Documentation]    && runs second command only if the first succeeds.
    ...                Payload: 127.0.0.1 && id
    [Tags]    command_injection    and_operator
    ${resp}=    Execute Ping Command    127.0.0.1 && id
    Should Not Contain    ${resp.text}    uid=
    ...    msg=id command output found — && injection succeeded!

CMD_TC05 - OR Operator Injection Is Blocked
    [Documentation]    || runs second command only if first FAILS.
    ...                Payload: invalid_host || id
    ...                Since ping to invalid_host fails, id executes.
    [Tags]    command_injection    or_operator
    ${resp}=    Execute Ping Command    invalid_host_xyz || id
    Should Not Contain    ${resp.text}    uid=
    ...    msg=id command output found — || injection succeeded!

# ------------------------------------------------------------------ #
#  PIPE INJECTION                                                      #
# ------------------------------------------------------------------ #

CMD_TC06 - Pipe Operator Injection Is Blocked
    [Documentation]    | pipes stdout of first command into second.
    ...                Payload: 127.0.0.1 | whoami
    [Tags]    command_injection    pipe
    ${resp}=    Execute Ping Command    127.0.0.1 | whoami
    Should Not Contain    ${resp.text}    www-data
    Should Not Contain    ${resp.text}    root

CMD_TC07 - Pipe To Cat Passwd Is Blocked
    [Documentation]    Payload: 127.0.0.1 | cat /etc/passwd
    [Tags]    command_injection    pipe    critical
    ${resp}=    Execute Ping Command    127.0.0.1 | cat /etc/passwd
    Response Should Not Expose System Files    ${resp}

# ------------------------------------------------------------------ #
#  TIME-BASED (BLIND) INJECTION                                        #
# ------------------------------------------------------------------ #

CMD_TC08 - Time-Based Command Injection Does Not Delay Response
    [Documentation]    If no visible output, time-based confirms injection.
    ...                Payload: 127.0.0.1; sleep 5
    ...                If the response takes 5+ seconds — injection works even without output.
    [Tags]    command_injection    time_based    blind
    ${start}=    Get Time    epoch
    Execute Ping Command    127.0.0.1; sleep 5
    ${end}=    Get Time    epoch
    ${elapsed}=    Evaluate    ${end} - ${start}
    Response Time Should Be Less Than    ${elapsed}    ${MAX_RESPONSE_TIME_SEC}
    Log    Time-based injection blocked. Response time: ${elapsed}s

# ------------------------------------------------------------------ #
#  WINDOWS-STYLE INJECTION                                             #
# ------------------------------------------------------------------ #

CMD_TC09 - Windows Command Separator Is Blocked
    [Documentation]    Windows uses & instead of ; as command separator.
    ...                Payload: 127.0.0.1 & dir
    ...                Tests cross-platform injection awareness.
    [Tags]    command_injection    windows
    ${resp}=    Execute Ping Command    127.0.0.1 & dir
    Should Not Contain    ${resp.text}    Volume in drive
    Should Not Contain    ${resp.text}    Directory of

# ------------------------------------------------------------------ #
#  INPUT VALIDATION BOUNDARY                                           #
# ------------------------------------------------------------------ #

CMD_TC10 - Non-IP Input Is Rejected
    [Documentation]    The endpoint expects an IP address. Non-IP input should be rejected
    ...                before ever reaching the OS command.
    [Tags]    command_injection    input_validation
    FOR    ${bad_input}    IN    hello    ../etc/passwd    <script>    DROP TABLE
        ${resp}=    Execute Ping Command    ${bad_input}
        Should Not Be Equal As Integers    ${resp.status_code}    500
        ...    msg=Server crashed on input: ${bad_input}
    END
    Log    All non-IP inputs handled without server error.
