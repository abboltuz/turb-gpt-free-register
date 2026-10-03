# -*- coding: utf-8 -*-
"""
Tests for pre-OAuth ChatGPT web warm-up (core/chat_warmup.py) and its
wiring into run_existing_account_oauth (verify_chat/import flow).

Guarantees:
1. With verify_chat=True the warm-up runs BEFORE any OAuth session or
   SMSFast purchase; warm-up failure returns failed/chat_warmup_unavailable
   with attempts=0 and zero purchases.
2. With verify_chat=False the warm-up is never invoked.
3. Warm-up helpers detect the chat UI, click Continue buttons and perform
   the login sequence against a fake playwright page.
"""
from unittest.mock import MagicMock, patch

import pytest

from core import chat_warmup
from core.existing_account_runner import SmsFastRunnerConfig, run_existing_account_oauth


class FakeLocator:
    def __init__(self, page, selector, visible=True):
        self.page = page
        self.selector = selector
        self._visible = visible
        self.filled = []

    @property
    def first(self):
        return self

    def wait_for(self, state="visible", timeout=3000):
        if not self._visible:
            raise TimeoutError("not visible")

    def is_visible(self):
        return self._visible

    def is_enabled(self):
        return self._visible

    def is_editable(self):
        return self._visible

    def fill(self, value, timeout=10000):
        self.filled.append(value)

    def click(self, timeout=5000):
        self.page.clicked.append(self.selector)

    def inner_text(self, timeout=1000):
        return self.page.button_text

    def count(self):
        return 1 if self._visible else 0

    def all(self):
        return [self] if self._visible else []


class FakeKeyboard:
    def __init__(self, page):
        self.page = page

    def press(self, key):
        self.page.keys.append(key)

    def type(self, value, delay=20):
        self.page.keys.append("type:" + str(len(str(value))))


class FakePage:
    """Simulates: login page with email box -> password -> chat UI."""

    def __init__(self):
        self.stage = "email"
        self.clicked = []
        self.keys = []
        self.keyboard = FakeKeyboard(self)
        self.button_text = "Continue"
        self.goto_urls = []
        self.url = ""

    def goto(self, url, wait_until="domcontentloaded", timeout=45000):
        self.goto_urls.append(url)
        self.url = url

    def title(self):
        return "fake"

    def locator(self, selector):
        if selector in chat_warmup.EMAIL_SELECTORS:
            return FakeLocator(self, selector, visible=(self.stage == "email"))
        if selector in chat_warmup.PASSWORD_SELECTORS:
            return FakeLocator(self, selector, visible=(self.stage == "password"))
        if selector in chat_warmup.CODE_SELECTORS:
            return FakeLocator(self, selector, visible=(self.stage == "code"))
        if selector in ('#prompt-textarea', 'textarea[data-testid]',
                        'div[contenteditable="true"]', "textarea"):
            return FakeLocator(self, selector, visible=(self.stage == "chat"))
        if selector.startswith("button"):
            return FakeLocator(self, selector, visible=True)
        return FakeLocator(self, selector, visible=False)

    def wait_for_function(self, *args, **kwargs):
        if self.stage != "chat":
            raise TimeoutError("no chat ui")


def test_chat_ui_present_only_in_chat_stage():
    page = FakePage()
    assert chat_warmup._chat_ui_present(page) is False
    page.stage = "chat"
    assert chat_warmup._chat_ui_present(page) is True


def test_fill_aborts_when_page_advances(monkeypatch):
    page = FakePage()
    urls = ["https://chatgpt.com/auth/login", "https://auth.openai.com/log-in/password"]
    page.url = urls[0]

    orig_editable = FakeLocator.is_editable
    calls = {"n": 0}

    def flaky_editable(self):
        calls["n"] += 1
        if calls["n"] > 2:
            page.url = urls[1]
        return False

    monkeypatch.setattr(FakeLocator, "is_editable", flaky_editable)
    monkeypatch.setattr(chat_warmup.time, "sleep", lambda s: None)
    with pytest.raises(chat_warmup._PageAdvanced):
        chat_warmup._fill_box(page, chat_warmup.EMAIL_SELECTORS, "x", label="email", timeout_ms=5000)
    monkeypatch.setattr(FakeLocator, "is_editable", orig_editable)


def test_web_login_happy_path_password_only(monkeypatch):
    page = FakePage()

    def fake_advance(pg, prev_url="", timeout_s=20):
        if page.stage == "email" and page.clicked:
            page.stage = "password"
        elif page.stage == "password" and page.clicked:
            page.stage = "chat"

    monkeypatch.setattr(chat_warmup.time, "sleep", lambda s: None)
    monkeypatch.setattr(chat_warmup, "_wait_for_page_advance", fake_advance)
    chat_warmup._web_login(page, "test@example.com", "secretpassword", None, None)
    assert page.goto_urls and page.goto_urls[0].startswith("https://chatgpt.com/")
    assert page.clicked, "Continue must have been clicked"


def test_web_login_fails_closed_when_chat_never_appears(monkeypatch):
    page = FakePage()
    page.stage = "stuck"
    monkeypatch.setattr(chat_warmup.time, "sleep", lambda s: None)
    monkeypatch.setattr(chat_warmup, "_settle_challenge", lambda page, timeout_s=30: None)
    monkeypatch.setattr(chat_warmup, "LOGIN_TIMEOUT", 0.01)
    with pytest.raises(chat_warmup.ChatWarmupUnavailableError):
        chat_warmup._web_login(page, "t@example.com", "pw", None, None)


def test_verify_chat_runs_warmup_before_oauth():
    config = SmsFastRunnerConfig(api_key="k", service="dr", countries=["54"])
    with patch("core.chat_warmup.warmup_chat_before_oauth") as warmup, \
         patch("core.existing_account_runner.ExistingAccountOAuthSession") as session_cls, \
         patch("core.existing_account_runner.SmsFastClient") as client_cls:
        warmup.return_value = {"reply_chars": 5}
        session_cls.side_effect = RuntimeError("oauth_must_not_run_first")
        res = run_existing_account_oauth(
            email="t@example.com", password="pw", proxy="http://1.2.3.4:8080",
            smsfast_config=config, verify_chat=True,
        )
    warmup.assert_called_once()
    # Warm-up ok, then OAuth failed on its own -> auth_flow_failed, attempts>=1.
    assert res.error_code == "auth_flow_failed"
    assert client_cls.return_value.acquire_number.call_count == 0


def test_warmup_failure_costs_nothing():
    config = SmsFastRunnerConfig(api_key="k", service="dr", countries=["54"])
    with patch("core.chat_warmup.warmup_chat_before_oauth",
               side_effect=chat_warmup.ChatWarmupUnavailableError("nope")), \
         patch("core.existing_account_runner.ExistingAccountOAuthSession") as session_cls, \
         patch("core.existing_account_runner.SmsFastClient") as client_cls:
        res = run_existing_account_oauth(
            email="t@example.com", password="pw", proxy="http://1.2.3.4:8080",
            smsfast_config=config, verify_chat=True,
        )
    assert res.ok is False
    assert res.status == "failed"
    assert res.error_code == "chat_warmup_unavailable"
    assert res.attempts == 0
    assert res.phone_used is False
    assert session_cls.call_count == 0
    assert client_cls.return_value.acquire_number.call_count == 0


def test_no_warmup_without_verify_chat():
    config = SmsFastRunnerConfig(api_key="k", service="dr", countries=["54"])
    with patch("core.chat_warmup.warmup_chat_before_oauth") as warmup, \
         patch("core.codex_oauth._bootstrap_authorize"), \
         patch("core.codex_oauth._submit_email", return_value={"page": {"type": "workspace"}}), \
         patch("core.codex_oauth._is_password_step", return_value=False), \
         patch("core.codex_oauth._is_email_otp_step", return_value=False), \
         patch("core.codex_oauth._is_phone_step", return_value=False), \
         patch("core.codex_oauth._generate_state", return_value="s"), \
         patch("core.codex_oauth._select_workspace_and_get_callback",
               return_value="http://localhost:1455/auth/callback?code=c&state=s"), \
         patch("core.codex_oauth.exchange_codex_token", return_value={
             "access_token": "t",
             "id_token": "header.eyJlbWFpbCI6ICJ0QGV4YW1wbGUuY29tIiwgImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6IHsiY2hhdGdwdF9hY2NvdW50X2lkIjogImFjY185OTkiLCAiY2hhdGdwdF9wbGFuX3R5cGUiOiAiZnJlZSJ9fQ.sig"}):
        res = run_existing_account_oauth(
            email="t@example.com", password="pw", proxy="http://1.2.3.4:8080",
            smsfast_config=config, verify_chat=False,
        )
    warmup.assert_not_called()
    assert res.ok is True
