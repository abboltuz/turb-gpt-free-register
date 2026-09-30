# -*- coding: utf-8 -*-
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import core.codex_oauth as codex


class _CodexSession:
    def __init__(self):
        self.calls = []
        self.reset_count = 0
        self.responses = [
            SimpleNamespace(status_code=403, text="blocked"),
            SimpleNamespace(status_code=200, text="ok", url="https://auth.openai.com/log-in"),
        ]

    def get_auth_navigate_headers(self, **kwargs):
        self.header_kwargs = kwargs
        return {"sec-fetch-site": "none"}

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)

    def reset_circuit_breaker(self):
        self.reset_count += 1


class CodexOauthFingerprintTests(unittest.TestCase):
    def test_auth_preflight_retries_403_in_same_session(self):
        session = _CodexSession()
        with patch.object(codex.time, "sleep") as sleep:
            codex._codex_auth_preflight(session)

        self.assertEqual(len(session.calls), 2)
        self.assertEqual(session.reset_count, 1)
        self.assertEqual(session.header_kwargs["referer"], "")
        self.assertFalse(session.header_kwargs["user_initiated"])
        sleep.assert_called_once_with(1.0)

    def test_bootstrap_authorize_uses_external_top_level_navigation_headers(self):
        session = _CodexSession()
        session.responses = [
            SimpleNamespace(status_code=200, text="ok", url="https://auth.openai.com/log-in")
        ]
        session.device_id = "device-id"
        session.auth_session_logging_id = "logging-id"

        codex._bootstrap_authorize(
            session,
            "state",
            auth_url="https://auth.openai.com/oauth/authorize?state=state",
        )

        self.assertEqual(session.header_kwargs["referer"], "")
        self.assertTrue(session.header_kwargs["user_initiated"])
        self.assertEqual(len(session.calls), 1)

    def test_bootstrap_authorize_does_not_route_transport_errors_to_browser(self):
        session = _CodexSession()
        session.responses = []

        def fail_transport(*_args, **_kwargs):
            raise RuntimeError("SOCKS transport failed")

        session.get = fail_transport
        with patch.object(codex, "_bootstrap_authorize_with_cloak") as browser_fallback:
            with self.assertRaisesRegex(RuntimeError, "SOCKS transport failed"):
                codex._bootstrap_authorize(
                    session,
                    "state",
                    auth_url="https://auth.openai.com/oauth/authorize?state=state",
                )
        browser_fallback.assert_not_called()

    def test_bootstrap_authorize_routes_http_403_to_browser_fallback(self):
        session = _CodexSession()
        response = SimpleNamespace(status_code=403, text="challenge")

        def fail_http(*_args, **_kwargs):
            error = RuntimeError("bootstrap authorize status=403")
            error.response = response
            raise error

        session.get = fail_http
        session.browser_profile = {}
        with patch.object(codex, "_bootstrap_authorize_with_cloak") as browser_fallback:
            codex._bootstrap_authorize(
                session,
                "state",
                auth_url="https://auth.openai.com/oauth/authorize?state=state",
            )
        browser_fallback.assert_called_once_with(session, "https://auth.openai.com/oauth/authorize?state=state")


if __name__ == "__main__":
    unittest.main()
