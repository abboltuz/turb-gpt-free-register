# -*- coding: utf-8 -*-
"""Tests for post-OAuth ChatGPT message+reply verification (mocked transport)."""
import json
import unittest
from types import SimpleNamespace

from core import chatgpt_verify
from core.chatgpt_verify import (
    ChatVerifyUnavailableError,
    verify_chat_reply,
)
from core.openai_auth import AccountUnusableError


def _resp(status=200, text="", as_json=None):
    payload = as_json if as_json is not None else text
    if isinstance(payload, (dict, list)):
        text = json.dumps(payload)
    else:
        text = payload
    def _json():
        return json.loads(text)
    return SimpleNamespace(status_code=status, text=text, json=_json)


SESSION_JSON = {"accessToken": "tok123", "user": {"email": "Test@Example.com"}}

ASSISTANT_MAPPING = {
    "mapping": {
        "u1": {"message": {"author": {"role": "user"},
                           "content": {"content_type": "text", "parts": ["ping"]}}},
        "a1": {"message": {"author": {"role": "assistant"},
                           "content": {"content_type": "text", "parts": ["pong reply here"]}}},
    }
}


class FakeSession:
    """Minimal BrowserSession double: canned get/post by URL substring."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get_chatgpt_navigate_headers(self, referer="", user_initiated=True):
        return {}

    def get_nextauth_headers(self, referer=""):
        return {}

    def _match(self, url):
        for key, resp in self.routes:
            if key in url:
                return resp
        raise AssertionError(f"unexpected url {url}")

    def get(self, url, headers=None, timeout=None, allow_redirects=False):
        self.calls.append(("GET", url))
        out = self._match(url)
        if isinstance(out, Exception):
            raise out
        return out

    def post(self, url, headers=None, data=None, timeout=None):
        self.calls.append(("POST", url))
        out = self._match(url)
        if isinstance(out, Exception):
            raise out
        return out


def _ok_session(extra=None):
    routes = [
        ("backend-api/conversation/", _resp(as_json=ASSISTANT_MAPPING)),
        ("backend-api/conversation", _resp(
            text='data: {"conversation_id":"conv1"}\ndata: [DONE]')),
        ("/api/auth/session", _resp(as_json=SESSION_JSON)),
        ("chatgpt.com/", _resp(status=200, text="<html/>")),
    ]
    if extra:
        routes = extra + routes
    return FakeSession(routes)


class ChatVerifyTests(unittest.TestCase):
    def test_reply_received(self):
        proof = verify_chat_reply(
            _ok_session(), "test@example.com",
            reply_timeout=5, poll_interval=0.01,
        )
        self.assertEqual(proof["conversation_id"], "conv1")
        self.assertGreater(proof["reply_chars"], 0)

    def test_dead_verdict_from_provider_code(self):
        session = _ok_session(extra=[
            ("backend-api/conversation", _resp(
                status=400, as_json={"error": {"code": "account_deactivated"}})),
        ])
        with self.assertRaises(AccountUnusableError) as ctx:
            verify_chat_reply(session, "test@example.com",
                              reply_timeout=5, poll_interval=0.01)
        self.assertEqual(ctx.exception.error_code, "account_deactivated")

    def test_challenge_is_unavailable_not_dead(self):
        session = _ok_session(extra=[
            ("backend-api/conversation", _resp(status=403, text="<html>challenge</html>")),
        ])
        with self.assertRaises(ChatVerifyUnavailableError):
            verify_chat_reply(session, "test@example.com",
                              reply_timeout=5, poll_interval=0.01)

    def test_empty_session_is_unavailable(self):
        session = _ok_session(extra=[
            ("/api/auth/session", _resp(as_json={})),
        ])
        with self.assertRaises(ChatVerifyUnavailableError):
            verify_chat_reply(session, "test@example.com",
                              reply_timeout=5, poll_interval=0.01)

    def test_reply_timeout_is_unavailable(self):
        waiting = {"mapping": {
            "u1": {"message": {"author": {"role": "user"},
                               "content": {"content_type": "text", "parts": ["ping"]}}},
        }}
        session = _ok_session(extra=[
            ("backend-api/conversation/", _resp(as_json=waiting)),
        ])
        with self.assertRaises(ChatVerifyUnavailableError):
            verify_chat_reply(session, "test@example.com",
                              reply_timeout=0.05, poll_interval=0.01)

    def test_logs_never_contain_message_content(self):
        session = _ok_session()
        with self.assertLogs("core.chatgpt_verify", level="INFO") as logs:
            verify_chat_reply(session, "test@example.com",
                              reply_timeout=5, poll_interval=0.01)
        blob = "\n".join(logs.output)
        self.assertNotIn("pong reply here", blob)
        self.assertNotIn("test@example.com", blob)


if __name__ == "__main__":
    unittest.main()
