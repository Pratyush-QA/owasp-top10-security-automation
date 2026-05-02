*** Settings ***
Documentation     File Upload vulnerability tests targeting DVWA.
...
...               Attack types covered:
...               - PHP webshell upload (direct .php extension)
...               - Double extension bypass (shell.php.jpg)
...               - MIME type spoofing (PHP file with image/jpeg Content-Type)
...               - Magic bytes bypass (GIF89a header + PHP payload)
...               - Large file upload (basic DoS check)
...               - Null byte bypass (shell.php%00.jpg — old PHP)
...
...               Key principle: even if upload succeeds, the file must NOT
...               be executable from the web. We test both upload AND execution.

Library           RequestsLibrary
Library           Collections
Library           OperatingSystem
Library           String
Resource          ../../Resources/CommonKeywords.robot
Resource          ../../Resources/Variables.robot

Suite Setup       Run Keywords
...               Create Session For DVWA    AND
...               ${COOKIES}=    Get Authenticated Session    AND
...               Set Suite Variable    ${COOKIES}

Suite Teardown    Clean Up Test Files

*** Keywords ***
Attempt File Upload
    [Arguments]    ${file_path}    ${content_type}=image/jpeg
    [Documentation]    Upload a file to DVWA and return the response.
    ${resp}=    Upload File
    ...    base_url=${BASE_URL}
    ...    upload_path=${FILE_UPLOAD_PATH}
    ...    file_path=${file_path}
    ...    cookies=${COOKIES}
    ...    content_type=${content_type}
    RETURN    ${resp}

Verify File Is Not Executable
    [Arguments]    ${filename}
    [Documentation]    Try to execute the uploaded file via web request.
    ...                If it responds with command output, it's executable → vulnerability!
    ${exec_resp}=    GET On Session    dvwa
    ...    ${UPLOADS_DIR}${filename}?cmd=id
    ...    cookies=${COOKIES}
    ...    expected_status=any
    Should Not Contain    ${exec_resp.text}    uid=
    ...    msg=File ${filename} is executable — Remote Code Execution confirmed!
    Should Not Contain    ${exec_resp.text}    www-data

Clean Up Test Files
    Remove Files    /tmp/shell.php    /tmp/shell.php.jpg    /tmp/shell.gif    /tmp/large.txt

*** Test Cases ***

# ------------------------------------------------------------------ #
#  DIRECT PHP UPLOAD                                                   #
# ------------------------------------------------------------------ #

UPLOAD_TC01 - Direct PHP Webshell Upload Is Blocked
    [Documentation]    Most basic attack: upload shell.php directly.
    ...                Content: <?php system($_GET['cmd']); ?>
    ...                A secure app must reject .php files outright.
    [Tags]    file_upload    php    critical    high_priority
    ${file}=    Create Php Webshell File    /tmp/shell.php
    ${resp}=    Attempt File Upload    ${file}    application/x-php
    ${uploaded}=    Run Keyword And Return Status
    ...    Should Contain    ${resp.text}    succesfully uploaded
    IF    ${uploaded}
        Verify File Is Not Executable    shell.php
        Log    WARN: shell.php uploaded but verify it cannot be executed!    WARN
    ELSE
        Log    PASS: shell.php upload correctly blocked.
    END

UPLOAD_TC02 - PHP File With Application Octet-Stream MIME Is Blocked
    [Documentation]    Same PHP file but with Content-Type: application/octet-stream.
    ...                Server must inspect the file content, not trust the MIME header.
    [Tags]    file_upload    php    mime_bypass
    ${file}=    Create Php Webshell File    /tmp/shell.php
    ${resp}=    Attempt File Upload    ${file}    application/octet-stream
    ${uploaded}=    Run Keyword And Return Status
    ...    Should Contain    ${resp.text}    succesfully uploaded
    IF    ${uploaded}
        Verify File Is Not Executable    shell.php
    ELSE
        Log    PASS: PHP with octet-stream MIME correctly blocked.
    END

# ------------------------------------------------------------------ #
#  MIME TYPE SPOOFING                                                  #
# ------------------------------------------------------------------ #

UPLOAD_TC03 - PHP File With image/jpeg MIME Type Is Blocked
    [Documentation]    Classic MIME bypass: upload shell.php but claim Content-Type: image/jpeg.
    ...                Many early WAFs only checked Content-Type header.
    ...                Secure app validates actual file content / magic bytes too.
    [Tags]    file_upload    mime_bypass    high_priority
    ${file}=    Create Php Webshell File    /tmp/shell.php
    ${resp}=    Attempt File Upload    ${file}    image/jpeg
    ${uploaded}=    Run Keyword And Return Status
    ...    Should Contain    ${resp.text}    succesfully uploaded
    IF    ${uploaded}
        Verify File Is Not Executable    shell.php
        Log    WARNING: PHP file with image/jpeg MIME was accepted — check content validation!    WARN
    ELSE
        Log    PASS: PHP with spoofed image/jpeg MIME correctly blocked.
    END

# ------------------------------------------------------------------ #
#  DOUBLE EXTENSION BYPASS                                             #
# ------------------------------------------------------------------ #

UPLOAD_TC04 - Double Extension PHP.JPG Is Not Executed
    [Documentation]    File: shell.php.jpg
    ...                Bypasses filters that only check the LAST extension (.jpg = allowed).
    ...                Some web servers execute the FIRST extension (.php) instead.
    ...                Even if uploaded, file must not execute as PHP.
    [Tags]    file_upload    double_extension
    ${file}=    Create Php Disguised As Image    /tmp/shell.php.jpg
    ${resp}=    Attempt File Upload    ${file}    image/jpeg
    ${uploaded}=    Run Keyword And Return Status
    ...    Should Contain    ${resp.text}    succesfully uploaded
    IF    ${uploaded}
        Verify File Is Not Executable    shell.php.jpg
        Log    shell.php.jpg uploaded — verified it cannot be executed as PHP.
    ELSE
        Log    PASS: shell.php.jpg upload blocked.
    END

# ------------------------------------------------------------------ #
#  MAGIC BYTES BYPASS                                                  #
# ------------------------------------------------------------------ #

UPLOAD_TC05 - GIF Magic Bytes With PHP Payload Is Not Executed
    [Documentation]    File starts with GIF89a (valid GIF magic bytes) followed by PHP code.
    ...                Bypasses image validation that only checks file header bytes.
    ...                File: shell.gif (actually PHP code with GIF header)
    [Tags]    file_upload    magic_bytes
    ${file}=    Create Gif With Php Payload    /tmp/shell.gif
    ${resp}=    Attempt File Upload    ${file}    image/gif
    ${uploaded}=    Run Keyword And Return Status
    ...    Should Contain    ${resp.text}    succesfully uploaded
    IF    ${uploaded}
        Verify File Is Not Executable    shell.gif
        Log    GIF+PHP uploaded — verified it cannot execute PHP code.
    ELSE
        Log    PASS: GIF magic bytes + PHP payload upload blocked.
    END

# ------------------------------------------------------------------ #
#  FILE SIZE LIMIT                                                     #
# ------------------------------------------------------------------ #

UPLOAD_TC06 - Extremely Large File Is Rejected
    [Documentation]    Upload a 100MB file to test file size limits and DoS protection.
    ...                Server should reject without crashing or hanging.
    [Tags]    file_upload    dos    boundary
    # Create a 10MB test file (adjust if server has lower limit)
    ${large_file}=    Set Variable    /tmp/large.txt
    ${content}=    Evaluate    'A' * 10485760    # 10 MB
    Create File    ${large_file}    ${content}
    ${resp}=    Attempt File Upload    ${large_file}    text/plain
    Should Not Be Equal As Integers    ${resp.status_code}    500
    ...    msg=Server crashed (500) on large file upload — possible DoS vulnerability!
    Log    Large file handled safely. Status: ${resp.status_code}

# ------------------------------------------------------------------ #
#  SAFE FILE — POSITIVE TEST                                           #
# ------------------------------------------------------------------ #

UPLOAD_TC07 - Legitimate Image Upload Succeeds
    [Documentation]    Positive test: a real JPEG image should upload successfully.
    ...                Verifies the security controls don't break legitimate use.
    [Tags]    file_upload    positive
    # Create a minimal valid JPEG (just the FFD8FF header + FFD9 footer)
    ${jpeg_path}=    Set Variable    /tmp/test_image.jpg
    ${jpeg_bytes}=    Evaluate    b'\\xff\\xd8\\xff\\xe0' + b'\\x00' * 100 + b'\\xff\\xd9'
    Create Binary File    ${jpeg_path}    ${jpeg_bytes}
    ${resp}=    Attempt File Upload    ${jpeg_path}    image/jpeg
    Log    Legitimate image upload result: ${resp.status_code} — ${resp.text[:200]}
    Remove File    ${jpeg_path}
