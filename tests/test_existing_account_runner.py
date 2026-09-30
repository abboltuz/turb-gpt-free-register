# -*- coding: utf-8 -*-
"""
Targeted tests for narrow existing-account runner (existing_account_runner.py).
Validates:
1. Proxy is strictly required; browser session missing proxy fails closed.
2. In-memory return only; no tokens/credentials written to disk or SQLite.
3. Fresh isolated session per attempt/retry.
4. Phone-only SMS purchase (no SMS number acquired if Auth does not demand phone).
5. Any exception after acquire_number (send fail, timeout, validate fail, stop) halts
   immediately with status='reconciliation_needed', preserves activation_id in reconciliation_data,
   and NEVER attempts a second getNumber purchase.
6. Error redaction: whitelisted typed error_codes and static messages only; no raw exception/URLs leaked.
7. Identity validation: claims email must match requested email and account_id must be present.
8. SmsFastRunnerConfig validation: requires explicit confirmed service, countries, timeout exactly 180s,
   max_retries_per_run bounds.
"""
from unittest.mock import MagicMock, patch
import pytest

from core.existing_account_runner import (
    ExistingAccountRunnerResult,
    SmsFastRunnerConfig,
    _proxy_url_for_oauth,
    mask_identifier,
    run_existing_account_oauth,
)
from core.smsfast_provider import (
    SmsFastNoBalanceError,
    SmsFastNoNumbersError,
    SmsFastReconciliationNeededError,
)


def test_smsfast_config_validation():
    """Requires explicit service, non-empty countries, timeout exactly 180s, retries bounded."""
    # Missing service
    with pytest.raises(ValueError, match="service is required"):
        SmsFastRunnerConfig(api_key="key", service="", countries=["10"])

    # Empty countries
    with pytest.raises(ValueError, match="non-empty list"):
        SmsFastRunnerConfig(api_key="key", service="dr", countries=[])

    # Timeout not 180
    with pytest.raises(ValueError, match="exactly 180 seconds"):
        SmsFastRunnerConfig(api_key="key", service="dr", countries=["10"], timeout=60)

    # Valid config
    cfg = SmsFastRunnerConfig(api_key="key", service="dr", countries=["10"], timeout=180, max_retries_per_run=3)
    assert cfg.timeout == 180
    assert cfg.service == "dr"


def test_oauth_proxy_uses_remote_dns_without_changing_proxy_endpoint_or_credentials():
    assert _proxy_url_for_oauth("socks5://user:pass@proxy.example:1234") == (
        "socks5h://user:pass@proxy.example:1234"
    )
    assert _proxy_url_for_oauth("http://user:pass@proxy.example:1234") == (
        "http://user:pass@proxy.example:1234"
    )


def test_entrypoint_empty_proxy_no_longer_blocked_first():
    """Empty proxy must not return proxy_required; validation proceeds to credentials."""
    res = run_existing_account_oauth(
        email="test@example.com",
        password="",
        proxy="",
    )
    assert res.ok is False
    assert res.error_code == "missing_credentials"


def test_missing_proxy_allows_direct_connection(monkeypatch, caplog):
    """No assigned proxy is allowed; BrowserSession receives an explicit empty proxy."""
    from core.existing_account_runner import ExistingAccountOAuthSession

    sessions = []

    class FakeBrowserSession:
        def __init__(self, **kwargs):
            sessions.append(kwargs)
            self.session = MagicMock()

        def close(self):
            pass

    monkeypatch.setattr("core.existing_account_runner.BrowserSession", FakeBrowserSession)
    with caplog.at_level("WARNING", logger="core.existing_account_runner"):
        session = ExistingAccountOAuthSession(email="test@example.com", password="secretpassword", proxy="")
    try:
        assert session.proxy is None
        assert sessions[0]["proxy"] == ""
        assert "without proxy (direct connection)" in caplog.text
    finally:
        session.close()


def test_browser_session_proxy_missing_fails_closed():
    """If BrowserSession fails to bind proxy, must fail closed immediately."""
    with patch("core.existing_account_runner.BrowserSession") as mock_bs_cls:
        mock_bs = MagicMock()
        mock_bs.session.proxies = {}  # Empty proxies
        mock_bs_cls.return_value = mock_bs

        res = run_existing_account_oauth(
            email="test@example.com",
            password="secretpassword",
            proxy="http://1.2.3.4:8080",
        )
        assert res.ok is False
        assert res.error_code == "proxy_configuration_invalid"
        assert res.redacted_error == "Configured proxy could not be applied to browser session."


def test_in_memory_success_without_disk_or_db_writes():
    """Successful OAuth run produces in-memory tokens/storage without db.upsert_codex_credential or file write."""
    fake_tokens = {
        "access_token": "secret_access_token_12345",
        "refresh_token": "secret_refresh_token_67890",
        "id_token": "header.eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIiwgImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6IHsiY2hhdGdwdF9hY2NvdW50X2lkIjogImFjY185OTkiLCAiY2hhdGdwdF9wbGFuX3R5cGUiOiAicHJvIn19.sig",
        "expires_in": 3600,
    }

    with patch("core.codex_oauth._bootstrap_authorize"), \
         patch("core.codex_oauth._submit_email", return_value={"page": {"type": "password"}}), \
         patch("core.codex_oauth._is_password_step", return_value=True), \
         patch("core.codex_oauth._password_verify", return_value={"page": {"type": "workspace"}}), \
         patch("core.codex_oauth._is_mfa_step", return_value=False), \
         patch("core.codex_oauth._is_email_otp_step", return_value=False), \
         patch("core.codex_oauth._is_phone_step", return_value=False), \
         patch("core.codex_oauth._follow_login_continue", return_value=None), \
         patch("core.codex_oauth._generate_state", return_value="mock_state"), \
         patch("core.codex_oauth._select_workspace_and_get_callback", return_value="http://localhost:1455/auth/callback?code=mock_code&state=mock_state"), \
         patch("core.codex_oauth.exchange_codex_token", return_value=fake_tokens), \
         patch("core.db.upsert_codex_credential") as mock_db_save:

        res = run_existing_account_oauth(
            email="test@example.com",
            password="secretpassword",
            proxy="http://1.2.3.4:8080",
        )

        assert res.ok is True
        assert res.status == "success"
        assert res.account_id == "acc_999"
        assert res.plan_type == "pro"
        assert res.tokens["access_token"] == "secret_access_token_12345"
        assert res.storage["access_token"] == "secret_access_token_12345"
        assert mock_db_save.call_count == 0


def test_identity_mismatch_fails_closed():
    """If id_token claims email differs from requested email, fail closed."""
    mismatched_tokens = {
        "access_token": "secret_access_token_12345",
        "refresh_token": "secret_refresh_token_67890",
        "id_token": "header.eyJlbWFpbCI6ICJvdGhlcl91c2VyQGV4YW1wbGUuY29tIiwgImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6IHsiY2hhdGdwdF9hY2NvdW50X2lkIjogImFjY185OTkiLCAiY2hhdGdwdF9wbGFuX3R5cGUiOiAicHJvIn19.sig",
        "expires_in": 3600,
    }

    with patch("core.codex_oauth._bootstrap_authorize"), \
         patch("core.codex_oauth._submit_email", return_value={"page": {"type": "password"}}), \
         patch("core.codex_oauth._is_password_step", return_value=True), \
         patch("core.codex_oauth._password_verify", return_value={"page": {"type": "workspace"}}), \
         patch("core.codex_oauth._is_mfa_step", return_value=False), \
         patch("core.codex_oauth._is_email_otp_step", return_value=False), \
         patch("core.codex_oauth._is_phone_step", return_value=False), \
         patch("core.codex_oauth._generate_state", return_value="mock_state"), \
         patch("core.codex_oauth._select_workspace_and_get_callback", return_value="http://localhost:1455/auth/callback?code=mock_code&state=mock_state"), \
         patch("core.codex_oauth.exchange_codex_token", return_value=mismatched_tokens):

        res = run_existing_account_oauth(
            email="test@example.com",
            password="secretpassword",
            proxy="http://1.2.3.4:8080",
        )

        assert res.ok is False
        assert res.status == "failed"
        assert res.error_code == "identity_mismatch"
        assert res.redacted_error == "Authenticated user identity email does not match requested email."


def test_missing_account_id_fails_closed():
    """If id_token claims lacks chatgpt_account_id, fail closed."""
    no_account_id_tokens = {
        "access_token": "tok",
        "id_token": "header.eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIn0.sig",
    }

    with patch("core.codex_oauth._bootstrap_authorize"), \
         patch("core.codex_oauth._submit_email", return_value={"page": {"type": "password"}}), \
         patch("core.codex_oauth._is_password_step", return_value=True), \
         patch("core.codex_oauth._password_verify", return_value={"page": {"type": "workspace"}}), \
         patch("core.codex_oauth._is_mfa_step", return_value=False), \
         patch("core.codex_oauth._is_email_otp_step", return_value=False), \
         patch("core.codex_oauth._is_phone_step", return_value=False), \
         patch("core.codex_oauth._generate_state", return_value="mock_state"), \
         patch("core.codex_oauth._select_workspace_and_get_callback", return_value="http://localhost:1455/auth/callback?code=mock_code&state=mock_state"), \
         patch("core.codex_oauth.exchange_codex_token", return_value=no_account_id_tokens):

        res = run_existing_account_oauth(
            email="test@example.com",
            password="secretpassword",
            proxy="http://1.2.3.4:8080",
        )

        assert res.ok is False
        assert res.status == "failed"
        assert res.error_code == "missing_account_id"
        assert res.redacted_error == "Authenticated user identity is missing account_id in token claims."


def test_phone_only_purchase_when_auth_prompts():
    """SMS Fast number is NOT purchased when phone step is not required."""
    mock_sms_client = MagicMock()
    config = SmsFastRunnerConfig(api_key="smsfast_test_key", service="dr", countries=["10"])

    with patch("core.existing_account_runner.SmsFastClient", return_value=mock_sms_client), \
         patch("core.codex_oauth._bootstrap_authorize"), \
         patch("core.codex_oauth._submit_email", return_value={"page": {"type": "password"}}), \
         patch("core.codex_oauth._is_password_step", return_value=True), \
         patch("core.codex_oauth._password_verify", return_value={"page": {"type": "workspace"}}), \
         patch("core.codex_oauth._is_mfa_step", return_value=False), \
         patch("core.codex_oauth._is_email_otp_step", return_value=False), \
         patch("core.codex_oauth._is_phone_step", return_value=False), \
         patch("core.codex_oauth._generate_state", return_value="mock_state"), \
         patch("core.codex_oauth._select_workspace_and_get_callback", return_value="http://localhost:1455/auth/callback?code=mock_code&state=mock_state"), \
         patch("core.codex_oauth.exchange_codex_token", return_value={"access_token": "tok", "id_token": "header.eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIiwgImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6IHsiY2hhdGdwdF9hY2NvdW50X2lkIjogImFjY185OTkiLCJjaGF0Z3B0X3BsYW5fdHlwZSI6ICJmcmVlIn19.sig"}):

        res = run_existing_account_oauth(
            email="test@example.com",
            password="secretpassword",
            proxy="http://1.2.3.4:8080",
            smsfast_config=config,
        )

        assert res.ok is True
        assert res.phone_used is False
        assert mock_sms_client.acquire_number.call_count == 0


def test_exception_after_acquire_halts_no_second_get_number():
    """
    ANY exception occurring after acquire_number (e.g. OpenAI add-phone/send fails,
    SMS timeout, or validate error) must halt immediately, set status='reconciliation_needed',
    record activation_id in reconciliation_data, and NEVER call acquire_number a second time!
    """
    config = SmsFastRunnerConfig(
        api_key="smsfast_test_key",
        service="dr",
        countries=["10", "20", "30"],
        max_retries_per_run=3,
    )

    mock_sms_client = MagicMock()
    mock_sms_client.acquire_number.return_value = ("act_45678", "16195366483")
    mock_sms_client.cancel_and_verify.return_value = True

    # Simulate OpenAI rejecting phone on add-phone/send
    with patch("core.existing_account_runner.SmsFastClient", return_value=mock_sms_client), \
         patch("core.codex_oauth._bootstrap_authorize"), \
         patch("core.codex_oauth._submit_email", return_value={"page": {"type": "password"}}), \
         patch("core.codex_oauth._is_password_step", return_value=True), \
         patch("core.codex_oauth._password_verify", return_value={"page": {"type": "phone-verification"}}), \
         patch("core.codex_oauth._is_mfa_step", return_value=False), \
         patch("core.codex_oauth._is_email_otp_step", return_value=False), \
         patch("core.codex_oauth._is_phone_step", return_value=True), \
         patch("core.codex_oauth._post_json", return_value=MagicMock(status_code=400)), \
         patch("core.codex_oauth._response_text", return_value='{"error":"invalid_phone"}'), \
         patch("core.codex_oauth._phone_failure_reason", return_value="invalid_phone"):

        res = run_existing_account_oauth(
            email="test@example.com",
            password="secretpassword",
            proxy="http://1.2.3.4:8080",
            smsfast_config=config,
        )

        assert res.ok is False
        assert res.status == "reconciliation_needed"
        # Crucial check: acquire_number called EXACTLY ONCE
        assert mock_sms_client.acquire_number.call_count == 1
        assert res.reconciliation_data is not None
        assert res.reconciliation_data["activation_id"] == "act_45678"
        assert res.error_code in ("sms_timeout_unverified_refund", "sms_order_failed_reconciliation")


def test_sms_timeout_halts_and_requires_reconciliation():
    """
    On 180s timeout, provider cancel_and_verify(ACCESS_CANCEL) is called, but because
    refund is unverified by API contract, runner fails closed without buying a 2nd number.
    """
    config = SmsFastRunnerConfig(
        api_key="smsfast_test_key",
        service="dr",
        countries=["10", "20"],
        max_retries_per_run=2,
    )

    mock_sms_client = MagicMock()
    mock_sms_client.acquire_number.return_value = ("act_99999", "16195366483")
    # Return STATUS_WAIT_CODE continuously
    mock_sms_client.get_status.return_value = ("STATUS_WAIT_CODE", None)
    mock_sms_client.cancel_and_verify.return_value = True

    # Mock time.time to allow start_wait and timeout check without exhausting calls for logging
    t = [1000.0]
    def fake_time():
        t[0] += 100.0
        return t[0]

    with patch("core.existing_account_runner.SmsFastClient", return_value=mock_sms_client), \
         patch("core.codex_oauth._bootstrap_authorize"), \
         patch("core.codex_oauth._submit_email", return_value={"page": {"type": "password"}}), \
         patch("core.codex_oauth._is_password_step", return_value=True), \
         patch("core.codex_oauth._password_verify", return_value={"page": {"type": "phone-verification"}}), \
         patch("core.codex_oauth._is_mfa_step", return_value=False), \
         patch("core.codex_oauth._is_email_otp_step", return_value=False), \
         patch("core.codex_oauth._is_phone_step", return_value=True), \
         patch("core.codex_oauth._post_json", return_value=MagicMock(status_code=200)), \
         patch("core.codex_oauth._response_text", return_value=""), \
         patch("core.codex_oauth._phone_failure_reason", return_value=""), \
         patch("time.sleep", return_value=None), \
         patch("time.time", side_effect=fake_time):

        res = run_existing_account_oauth(
            email="test@example.com",
            password="secretpassword",
            proxy="http://1.2.3.4:8080",
            smsfast_config=config,
        )

        assert res.ok is False
        assert res.status == "reconciliation_needed"
        assert res.error_code == "sms_timeout_unverified_refund"
        # Zero additional attempts allowed!
        assert mock_sms_client.acquire_number.call_count == 1
        assert res.reconciliation_data["activation_id"] == "act_99999"


def test_redaction_strict_whitelist_no_raw_exc_or_urls():
    """Ensure no raw URLs, tokens, passwords, or query strings leak into error_code or redacted_error."""
    raw_leaked_string = "Error at https://smsfastapi.com?api_key=SECRET123 password=MyPassword456 token=eyJ..."

    with patch("core.codex_oauth._bootstrap_authorize", side_effect=RuntimeError(raw_leaked_string)):
        res = run_existing_account_oauth(
            email="mysecretemail@example.com",
            password="MyPassword456",
            proxy="http://proxy:8080",
        )

        assert res.ok is False
        # Whitelisted code and message
        assert res.error_code == "auth_flow_failed"
        assert res.redacted_error == "Authentication process failed during OAuth handshake."
        assert "SECRET123" not in res.redacted_error
        assert "MyPassword456" not in res.redacted_error
        assert "https://" not in res.redacted_error
        assert res.email == "my***@example.com"


def test_unexpected_oauth_error_logs_type_only(caplog):
    """Unexpected runner errors are diagnosable without logging their contents."""
    import logging

    secret_error = "https://auth.openai.com/?token=secret-value password=secret-password"
    with patch("core.codex_oauth._bootstrap_authorize", side_effect=RuntimeError(secret_error)):
        with caplog.at_level(logging.WARNING, logger="core.existing_account_runner"):
            result = run_existing_account_oauth(
                email="test@example.com",
                password="secret-password",
                proxy="http://proxy:8080",
            )

    assert result.error_code == "auth_flow_failed"
    assert "phase=oauth_flow exception_type=RuntimeError" in caplog.text
    assert "secret-value" not in caplog.text
    assert "secret-password" not in caplog.text
    assert "auth.openai.com" not in caplog.text


def test_runner_init_error_logs_session_phase(caplog):
    """Session construction errors are distinguished from OAuth protocol failures."""
    import logging

    with patch("core.existing_account_runner.BrowserSession", side_effect=OSError("private detail")):
        with caplog.at_level(logging.WARNING, logger="core.existing_account_runner"):
            result = run_existing_account_oauth(
                email="test@example.com",
                password="secret-password",
                proxy="socks5://user:password@proxy.example:1234",
            )

    assert result.error_code == "auth_flow_failed"
    assert "phase=session_init exception_type=OSError" in caplog.text
    assert "private detail" not in caplog.text
    assert "proxy.example" not in caplog.text
