import base64
import io
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash

import app_debug_off as dashboard


class DashboardSecurityTests(unittest.TestCase):
    def setUp(self):
        self.old_username = dashboard.DASHBOARD_USERNAME
        self.old_password_hash = dashboard.DASHBOARD_PASSWORD_HASH
        self.old_testing = dashboard.app.config.get("TESTING", False)
        dashboard.DASHBOARD_USERNAME = "dashboard-user"
        dashboard.DASHBOARD_PASSWORD_HASH = generate_password_hash(
            "long-test-password"
        )
        dashboard.app.config["TESTING"] = True
        with dashboard._login_failures_lock:
            dashboard._login_failures.clear()
        self.client = dashboard.app.test_client()

    def tearDown(self):
        with dashboard._login_failures_lock:
            dashboard._login_failures.clear()
        dashboard.DASHBOARD_USERNAME = self.old_username
        dashboard.DASHBOARD_PASSWORD_HASH = self.old_password_hash
        dashboard.app.config["TESTING"] = self.old_testing

    @staticmethod
    def auth_header(username, password):
        credentials = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {credentials}"}

    def get_dashboard(self, address, headers=None):
        return self.client.get(
            "/",
            headers=headers,
            environ_overrides={"REMOTE_ADDR": address},
        )

    def test_auth_responses_include_anti_framing_headers(self):
        response = self.get_dashboard("192.0.2.10")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            "frame-ancestors 'none'",
        )

    def test_password_hash_command_never_prints_the_plaintext(self):
        password = "long-test-password"
        output = io.StringIO()
        with patch.object(
            dashboard.getpass, "getpass", side_effect=[password, password]
        ), patch.object(
            sys, "argv", ["app_debug_off.py", "--generate-password-hash"]
        ), redirect_stdout(output):
            dashboard.main()

        password_hash = output.getvalue().strip()
        self.assertNotEqual(password_hash, password)
        self.assertTrue(check_password_hash(password_hash, password))

    def test_five_failures_lock_out_only_that_client(self):
        bad_credentials = self.auth_header("dashboard-user", "wrong-password")
        for attempt in range(dashboard.FAILED_LOGIN_LIMIT):
            response = self.get_dashboard("192.0.2.11", bad_credentials)
            if attempt < dashboard.FAILED_LOGIN_LIMIT - 1:
                self.assertEqual(response.status_code, 401)
            else:
                self.assertEqual(response.status_code, 429)
                self.assertEqual(
                    response.headers["Retry-After"],
                    str(dashboard.LOGIN_LOCKOUT_SECONDS),
                )

        valid_credentials = self.auth_header(
            "dashboard-user", "long-test-password"
        )
        locked_response = self.get_dashboard("192.0.2.11", valid_credentials)
        other_client_response = self.get_dashboard(
            "192.0.2.12", valid_credentials
        )
        self.assertEqual(locked_response.status_code, 429)
        self.assertEqual(other_client_response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
