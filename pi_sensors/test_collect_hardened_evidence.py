import unittest

from pi_sensors.collect_hardened_evidence import (
    add_deployed_service_checks,
    normalize_source_cidr,
    validate_ufw_policy,
)


class UfwPolicyTests(unittest.TestCase):
    def test_accepts_only_expected_tcp_rules_from_the_expected_host(self):
        status = (
            "Status: active\n"
            "Logging: on (low)\n"
            "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
        )
        rules = (
            "To                         Action      From\n"
            "--                         ------      ----\n"
            "[ 1] 22/tcp                 ALLOW IN    192.0.2.10\n"
            "[ 2] 443/tcp                ALLOW IN    192.0.2.10\n"
        )

        result = validate_ufw_policy(status, rules, "192.0.2.10/32")

        self.assertTrue(result["compliant"])

    def test_rejects_an_additional_open_port_or_broad_source(self):
        status = (
            "Status: active\n"
            "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
        )
        rules = (
            "[ 1] 22/tcp ALLOW IN 192.0.2.10\n"
            "[ 2] 443/tcp ALLOW IN 192.0.2.10\n"
            "[ 3] 5001/tcp ALLOW IN Anywhere\n"
        )

        result = validate_ufw_policy(status, rules, "192.0.2.10")

        self.assertFalse(result["compliant"])

    def test_requires_active_firewall_and_default_deny(self):
        rules = (
            "[ 1] 22/tcp ALLOW IN 192.0.2.10\n"
            "[ 2] 443/tcp ALLOW IN 192.0.2.10\n"
        )

        result = validate_ufw_policy(
            "Status: inactive\nDefault: allow (incoming), allow (outgoing)",
            rules,
            "192.0.2.10/32",
        )

        self.assertFalse(result["compliant"])

    def test_normalizes_plain_ip_to_host_cidr_and_rejects_invalid_input(self):
        self.assertEqual(normalize_source_cidr("192.0.2.10"), "192.0.2.10/32")
        with self.assertRaises(ValueError):
            normalize_source_cidr("not-an-address")

    def test_deployed_listener_check_requires_public_443_and_loopback_gunicorn(self):
        listeners = (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:5001 0.0.0.0:*\n"
        )
        inventory = {
            "commands": {
                "nginx_service": {"status": "COMPLETED", "output": "active"},
                "nginx_config_test": {"status": "COMPLETED", "exit_code": 0},
                "dashboard_service": {"status": "COMPLETED", "output": "active"},
                "listeners_unprivileged": {
                    "status": "COMPLETED",
                    "output": listeners,
                },
            },
            "nginx_facts": {
                "https_443_listener": True,
                "proxy_to_loopback_gunicorn": True,
                "forwarded_client_ip_overwritten": True,
                "enabled_site_files": ["sensor-dashboard"],
            },
        }
        checks = []

        add_deployed_service_checks(checks, inventory)

        by_name = {check["name"]: check["status"] for check in checks}
        self.assertEqual(by_name["Deployed Nginx service"], "PASS")
        self.assertEqual(
            by_name["Deployed Nginx reverse-proxy configuration"], "PASS"
        )
        self.assertEqual(by_name["Deployed Gunicorn service"], "PASS")
        self.assertEqual(by_name["Deployed listener exposure"], "PASS")

    def test_deployed_listener_check_rejects_network_bound_gunicorn(self):
        inventory = {
            "commands": {
                "listeners_unprivileged": {
                    "status": "COMPLETED",
                    "output": (
                        "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
                        "tcp LISTEN 0 128 0.0.0.0:5001 0.0.0.0:*\n"
                    ),
                },
            },
            "nginx_facts": {},
        }
        checks = []

        add_deployed_service_checks(checks, inventory)

        listeners = next(
            check for check in checks
            if check["name"] == "Deployed listener exposure"
        )
        self.assertEqual(listeners["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
