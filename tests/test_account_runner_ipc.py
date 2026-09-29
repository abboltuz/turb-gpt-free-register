# -*- coding: utf-8 -*-
import os
import socket
import struct
import tempfile
import time
import unittest

from core.account_runner_ipc import (
    ExistingAccountIPCDaemon,
    read_framed_json,
    write_framed_json,
    MAX_MESSAGE_BYTES,
)
from core.existing_account_runner import ExistingAccountRunnerResult


class TestExistingAccountIPC(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.temp_dir.name, "test_runner.sock")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ipc_permissions_and_ping(self):
        daemon = ExistingAccountIPCDaemon(self.sock_path)
        daemon.start()
        try:
            # Check permissions 0600 (only user read/write)
            stat = os.stat(self.sock_path)
            mode = stat.st_mode & 0o777
            self.assertEqual(mode, 0o600)

            # Connect and ping
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            write_framed_json(client, {"action": "ping"})
            resp = read_framed_json(client)
            self.assertTrue(resp.get("ok"))
            self.assertEqual(resp.get("status"), "pong")
            client.close()
        finally:
            daemon.stop()

    def test_live_socket_is_not_replaced(self):
        first = ExistingAccountIPCDaemon(self.sock_path)
        first.start()
        try:
            second = ExistingAccountIPCDaemon(self.sock_path)
            with self.assertRaises(RuntimeError):
                second.start()
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(self.sock_path)
                write_framed_json(client, {"action": "ping"})
                self.assertEqual(read_framed_json(client)["status"], "pong")
            finally:
                client.close()
        finally:
            first.stop()

    def test_ipc_mock_success(self):
        def mock_runner(email, password, proxy, **kwargs):
            return ExistingAccountRunnerResult(
                ok=True,
                status="success",
                email=email,
                account_id="acc-12345",
                plan_type="plus",
                tokens={"access_token": "mock-access-token", "refresh_token": "mock-refresh-token"},
                storage={"account_id": "acc-12345"},
                attempts=1,
            )

        daemon = ExistingAccountIPCDaemon(self.sock_path, runner_fn=mock_runner)
        daemon.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            write_framed_json(
                client,
                {
                    "action": "run_existing_oauth",
                    "email": "user@example.com",
                    "password": "secretpassword",
                    "proxy": "http://127.0.0.1:8080",
                },
            )
            resp = read_framed_json(client)
            self.assertTrue(resp.get("ok"))
            self.assertEqual(resp.get("status"), "success")
            self.assertEqual(resp.get("email"), "user@example.com")
            self.assertEqual(resp.get("account_id"), "acc-12345")
            self.assertIn("tokens", resp)
            self.assertEqual(resp["tokens"]["access_token"], "mock-access-token")
            client.close()
        finally:
            daemon.stop()

    def test_ipc_mock_failure(self):
        def mock_runner(email, password, proxy, **kwargs):
            return ExistingAccountRunnerResult(
                ok=False,
                status="failed",
                email="us***@example.com",
                error_code="proxy_required",
                redacted_error="Proxy configuration is strictly required (direct connection forbidden).",
                attempts=1,
            )

        daemon = ExistingAccountIPCDaemon(self.sock_path, runner_fn=mock_runner)
        daemon.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            write_framed_json(
                client,
                {
                    "action": "run_existing_oauth",
                    "email": "user@example.com",
                    "password": "secretpassword",
                    "proxy": "",
                },
            )
            resp = read_framed_json(client)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("status"), "failed")
            self.assertEqual(resp.get("error_code"), "proxy_required")
            self.assertIsNone(resp.get("tokens"))
            client.close()
        finally:
            daemon.stop()

    def test_ipc_mock_reconciliation(self):
        def mock_runner(email, password, proxy, **kwargs):
            return ExistingAccountRunnerResult(
                ok=False,
                status="reconciliation_needed",
                email="us***@example.com",
                error_code="sms_timeout_unverified_refund",
                redacted_error="SMS timeout occurred; refund confirmation cannot be independently verified. Fail closed.",
                attempts=1,
                phone_used=True,
                reconciliation_data={"activation_id": "act-999000", "country": "us", "attempt": 1},
            )

        daemon = ExistingAccountIPCDaemon(self.sock_path, runner_fn=mock_runner)
        daemon.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            write_framed_json(
                client,
                {
                    "action": "run_existing_oauth",
                    "email": "user@example.com",
                    "password": "secretpassword",
                    "proxy": "http://127.0.0.1:8080",
                    "smsfast_config": {
                        "api_key": "dummy-key",
                        "service": "openai",
                        "countries": ["us"],
                    },
                },
            )
            resp = read_framed_json(client)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("status"), "reconciliation_needed")
            self.assertEqual(resp.get("error_code"), "sms_timeout_unverified_refund")
            self.assertTrue(resp.get("phone_used"))
            self.assertEqual(resp.get("reconciliation_data", {}).get("activation_id"), "act-999000")
            client.close()
        finally:
            daemon.stop()

    def test_ipc_email_otp_prompt_and_delivery(self):
        # Verify two-way interactive prompt: Turb runner challenges with event without secrets,
        # Go client replies with one-time code, runner succeeds.
        def mock_runner_with_otp(email, password, proxy, email_otp_callback=None, **kwargs):
            if email_otp_callback is None:
                return ExistingAccountRunnerResult(
                    ok=False,
                    status="failed",
                    email=email,
                    error_code="auth_requires_email_otp",
                    redacted_error="Email OTP verification requested but no callback provided.",
                )
            # Invoke callback: should trigger framed prompt event to client
            code = email_otp_callback(email, time.time())
            if code == "123456":
                return ExistingAccountRunnerResult(
                    ok=True,
                    status="success",
                    email=email,
                    account_id="acc-otp-success",
                    tokens={"access_token": "token-after-otp"},
                )
            return ExistingAccountRunnerResult(
                ok=False,
                status="failed",
                email=email,
                error_code="auth_flow_failed",
                redacted_error="Invalid OTP code",
            )

        daemon = ExistingAccountIPCDaemon(self.sock_path, runner_fn=mock_runner_with_otp)
        daemon.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            # 1. Send run_existing_oauth with manual email OTP mode
            write_framed_json(
                client,
                {
                    "action": "run_existing_oauth",
                    "email": "user@example.com",
                    "password": "secretpassword",
                    "proxy": "http://127.0.0.1:8080",
                    "email_otp_mode": "manual",
                },
            )

            # 2. Expect email_otp_prompt event from runner (NO SECRETS in payload)
            prompt = read_framed_json(client)
            self.assertEqual(prompt.get("event"), "email_otp_prompt")
            self.assertEqual(prompt.get("email"), "user@example.com")
            self.assertNotIn("password", prompt)
            self.assertNotIn("totp_secret", prompt)

            # 3. Respond with OTP code
            write_framed_json(
                client,
                {
                    "action": "submit_email_otp",
                    "code": "123456",
                },
            )

            # 4. Final success response from runner
            resp = read_framed_json(client)
            self.assertTrue(resp.get("ok"))
            self.assertEqual(resp.get("status"), "success")
            self.assertEqual(resp.get("account_id"), "acc-otp-success")
            client.close()
        finally:
            daemon.stop()

    def test_ipc_email_otp_cancel_or_empty_fail_closed(self):
        def mock_runner_with_otp(email, password, proxy, email_otp_callback=None, **kwargs):
            if email_otp_callback:
                try:
                    email_otp_callback(email, time.time())
                except RuntimeError as exc:
                    return ExistingAccountRunnerResult(
                        ok=False,
                        status="failed",
                        email=email,
                        error_code="email_otp_cancelled",
                        redacted_error=f"Cancelled: {str(exc)}",
                    )
            return ExistingAccountRunnerResult(ok=False, status="failed", email=email, error_code="auth_flow_failed")

        daemon = ExistingAccountIPCDaemon(self.sock_path, runner_fn=mock_runner_with_otp)
        daemon.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            write_framed_json(
                client,
                {
                    "action": "run_existing_oauth",
                    "email": "user@example.com",
                    "password": "secretpassword",
                    "proxy": "http://127.0.0.1:8080",
                    "email_otp_mode": "manual",
                },
            )
            prompt = read_framed_json(client)
            self.assertEqual(prompt.get("event"), "email_otp_prompt")

            # Reply with cancel
            write_framed_json(client, {"action": "cancel_email_otp"})

            resp = read_framed_json(client)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("error_code"), "email_otp_cancelled")
            client.close()
        finally:
            daemon.stop()

    def test_ipc_auto_email_otp_skips_manual_prompt(self):
        received = {}

        def mock_runner(email, password, proxy, email_otp_callback=None, **kwargs):
            received.update(kwargs)
            self.assertIsNone(email_otp_callback)
            return ExistingAccountRunnerResult(ok=True, status="success", email=email, account_id="auto-otp")

        daemon = ExistingAccountIPCDaemon(self.sock_path, runner_fn=mock_runner)
        daemon.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            write_framed_json(client, {
                "action": "run_existing_oauth",
                "email": "user@example.com",
                "password": "secretpassword",
                "proxy": "http://127.0.0.1:8080",
                "email_otp_mode": "auto",
                "mail_provider": "generic_api",
            })
            response = read_framed_json(client)
            self.assertTrue(response.get("ok"))
            self.assertEqual(received.get("email_otp_mode"), "auto")
            self.assertEqual(received.get("mail_provider"), "generic_api")
            client.close()
        finally:
            daemon.stop()

    def test_ipc_body_limit(self):
        daemon = ExistingAccountIPCDaemon(self.sock_path)
        daemon.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self.sock_path)
            # Send length exceeding MAX_MESSAGE_BYTES
            huge_length = MAX_MESSAGE_BYTES + 1024
            client.sendall(struct.pack("!I", huge_length))
            # The daemon should abort / send error response
            resp = read_framed_json(client)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("error_code"), "ipc_error")
            client.close()
        finally:
            daemon.stop()


if __name__ == "__main__":
    unittest.main()
