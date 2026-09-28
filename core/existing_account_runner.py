# -*- coding: utf-8 -*-
"""
Existing Account OAuth Runner for Sub2API Account Manager.

Narrow, memory-only caller function for re-authorizing / importing existing OpenAI
accounts without touching disk/SQLite, without global config fallback for proxy,
with strict session isolation, explicit phone-only SMS purchase, and fail-closed
ambiguous cancellation semantics.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from core import codex_oauth
from core.openai_auth import AccountUnusableError
from core.session import BrowserSession
from core.smsfast_provider import (
    SmsFastClient,
    SmsFastError,
    SmsFastNoBalanceError,
    SmsFastNoNumbersError,
    SmsFastReconciliationNeededError,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Whitelist of typed error codes and safe static descriptions
# ---------------------------------------------------------------------------
ERROR_CODE_WHITELIST = {
    "proxy_required": "Proxy configuration is strictly required (direct connection forbidden).",
    "proxy_configuration_invalid": "Configured proxy could not be applied to browser session.",
    "missing_credentials": "Email and password are required.",
    "identity_mismatch": "Authenticated user identity email does not match requested email.",
    "missing_account_id": "Authenticated user identity is missing account_id in token claims.",
    "account_deactivated": "OpenAI account has been deactivated or banned.",
    "account_deleted": "OpenAI account has been deleted.",
    "account_unusable": "OpenAI account cannot be used.",
    "auth_requires_mfa": "MFA is required but no valid TOTP secret was provided.",
    "auth_requires_email_otp": "Email OTP verification requested but no callback provided.",
    "email_otp_timeout": "Email OTP input timed out.",
    "email_otp_cancelled": "Email OTP input was cancelled.",
    "auth_requires_phone": "Phone verification requested but SMSFast is not configured.",
    "smsfast_no_balance": "Insufficient balance on SMSFast account.",
    "smsfast_no_numbers": "No SMS phone numbers available for specified countries.",
    "smsfast_invalid_key": "Invalid SMSFast API key.",
    "sms_reconciliation_needed": "SMS activation state requires reconciliation. Purchase halted to prevent extra charges.",
    "sms_timeout_unverified_refund": "SMS timeout occurred; refund confirmation cannot be independently verified. Fail closed.",
    "sms_order_failed_reconciliation": "Error occurred after number purchase. Fail closed; reconciliation required.",
    "auth_flow_failed": "Authentication process failed during OAuth handshake.",
    "max_retries_exceeded": "Maximum authorization retries exceeded.",
}


@dataclass(frozen=True)
class SmsFastRunnerConfig:
    api_key: str
    service: str
    countries: list[str]
    base_url: str = "https://smsfastapi.com/stubs/handler_api.php"
    max_price: str | None = None
    timeout: int = 180  # Exactly 180s per ТЗ
    poll_interval: int = 5
    max_retries_per_run: int = 3

    def __post_init__(self):
        if not self.api_key or not str(self.api_key).strip():
            raise ValueError("SmsFastRunnerConfig.api_key is required")
        if not self.service or not str(self.service).strip():
            raise ValueError("SmsFastRunnerConfig.service is required (no implicit default)")
        if not self.countries or not isinstance(self.countries, (list, tuple)):
            raise ValueError("SmsFastRunnerConfig.countries must be a non-empty list of country codes")
        if self.timeout != 180:
            raise ValueError("SmsFastRunnerConfig.timeout must be exactly 180 seconds per ТЗ")
        if self.max_retries_per_run < 1 or self.max_retries_per_run > 5:
            raise ValueError("SmsFastRunnerConfig.max_retries_per_run must be between 1 and 5")


@dataclass(frozen=True)
class ExistingAccountRunnerResult:
    ok: bool
    status: str  # "success", "failed", "deactivated", "reconciliation_needed"
    email: str
    account_id: str | None = None
    plan_type: str | None = None
    tokens: dict[str, Any] | None = None  # in-memory only: access_token, refresh_token, id_token, expires_in, etc.
    storage: dict[str, Any] | None = None  # in-memory CLIProxyAPI/Sub2API compatible storage payload
    error_code: str | None = None
    redacted_error: str | None = None
    attempts: int = 0
    phone_used: bool = False
    reconciliation_data: dict[str, Any] | None = None  # Secure internal diagnostic state for manual reconciliation


def mask_identifier(val: str | None) -> str:
    """Mask sensitive string (email or phone or key) for safe reporting."""
    if not val:
        return ""
    s = str(val).strip()
    if "@" in s:
        parts = s.split("@", 1)
        name = parts[0]
        domain = parts[1]
        if len(name) <= 2:
            masked_name = name[:1] + "***"
        else:
            masked_name = name[:2] + "***"
        return f"{masked_name}@{domain}"
    if len(s) <= 4:
        return "***"
    return s[:2] + "***" + s[-2:]


def _get_static_error(code: str, fallback_code: str = "auth_flow_failed") -> tuple[str, str]:
    """Returns static whitelisted error code and its static description (never raw exception text)."""
    if code in ERROR_CODE_WHITELIST:
        return code, ERROR_CODE_WHITELIST[code]
    if fallback_code in ERROR_CODE_WHITELIST:
        return fallback_code, ERROR_CODE_WHITELIST[fallback_code]
    return "auth_flow_failed", ERROR_CODE_WHITELIST["auth_flow_failed"]


class ExistingAccountOAuthSession:
    """
    Encapsulates one fresh, isolated OAuth session for an existing account.
    Strictly binds to a specific required proxy; no fallback to direct or global pool.
    Always uses fresh local PKCE and state for each session.
    """

    def __init__(
        self,
        email: str,
        proxy: str,
        password: str,
        totp_secret: str | None = None,
        email_otp_callback: Callable[[str, float], str] | None = None,
    ):
        if not proxy or not str(proxy).strip():
            raise ValueError("Proxy is strictly required for ExistingAccountOAuthSession (no direct fallback allowed)")
        if not email or not str(email).strip():
            raise ValueError("Email is required")
        if not password:
            raise ValueError("Password is required for existing account runner")

        self.email = str(email).strip().lower()
        self.proxy = str(proxy).strip()
        self.password = str(password)
        self.totp_secret = str(totp_secret).strip() if totp_secret else None
        self.email_otp_callback = email_otp_callback

        self.session_id = str(uuid.uuid4())
        self.fingerprint_seed = f"sub2api-existing:{self.email}:{self.session_id}"

        # Create isolated BrowserSession with explicit proxy and detect_exit_geo=False
        self.session = BrowserSession(
            proxy=self.proxy,
            fingerprint_seed=self.fingerprint_seed,
            detect_exit_geo=False,
        )

        # Enforce that BrowserSession has configured proxies; fail closed if proxy missing
        configured_proxies = getattr(self.session.session, "proxies", None) or {}
        if not configured_proxies.get("http") or not configured_proxies.get("https"):
            self.session.close()
            raise ValueError("BrowserSession failed to bind configured proxy. Fail-closed: direct connection forbidden.")

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass

    def execute_flow(
        self,
        smsfast_config: SmsFastRunnerConfig | None = None,
        on_phone_prompt_needed: Callable[[], tuple[dict[str, Any], str, str]] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], bool, str | None]:
        """
        Runs the OAuth flow up to code exchange and returns:
          (tokens_dict, id_claims_dict, phone_used, activation_id_if_acquired)
        Does NOT write to disk or SQLite database.
        Always generates fresh PKCE & state.
        """
        # Step 1: Fresh local PKCE & state
        code_verifier, code_challenge = codex_oauth._generate_pkce()
        state = codex_oauth._generate_state()
        auth_url = codex_oauth._build_authorize_url(state, code_challenge, prompt="login")

        # Step 2: Bootstrap session
        codex_oauth._bootstrap_authorize(self.session, state, auth_url=auth_url)

        # Step 3: Submit email
        otp_after_ts = time.time()
        auth_result = codex_oauth._submit_email(self.session, self.email)

        # Step 4: Password login
        login_status = "not_applicable"
        early_callback_url = None

        if codex_oauth._is_password_step(auth_result):
            pwd_result = codex_oauth._password_verify(self.session, self.password)
            continue_url = codex_oauth._extract_continue_url(pwd_result)
            page_type = codex_oauth._page_type(pwd_result)

            if codex_oauth._is_mfa_step(pwd_result, continue_url) or page_type == "mfa_challenge":
                if not self.totp_secret:
                    raise RuntimeError("auth_requires_mfa")
                import pyotp
                factor_id = codex_oauth._extract_factor_id(pwd_result, continue_url)
                if not factor_id:
                    raise RuntimeError("auth_requires_mfa")
                codex_oauth._mfa_issue_challenge(self.session, factor_id)
                totp_code = pyotp.TOTP(self.totp_secret).now()
                pwd_result = codex_oauth._mfa_verify(self.session, factor_id, totp_code)
                continue_url = codex_oauth._extract_continue_url(pwd_result) or continue_url

            if codex_oauth._is_email_otp_step(pwd_result) or page_type in {"email_verification", "email_otp_send"}:
                login_status = "email_otp"
                auth_result = pwd_result
            else:
                early_callback_url = codex_oauth._follow_login_continue(self.session, continue_url, state) if continue_url else None
                login_status = "logged_in"
                auth_result = pwd_result

        # Step 5: Email OTP if prompted
        password_login_done = login_status == "logged_in"
        if not password_login_done and (
            login_status == "email_otp" or codex_oauth._is_email_otp_step(auth_result)
        ):
            if not self.email_otp_callback:
                raise RuntimeError("auth_requires_email_otp")
            email_otp = self.email_otp_callback(self.email, otp_after_ts)
            auth_result = codex_oauth._submit_email_otp(self.session, email_otp)

        # Step 6: Phone verification ONLY if required by Auth
        phone_used = False
        last_activation_id = None
        if codex_oauth._is_phone_step(auth_result):
            phone_used = True
            logger.info(f"[ExistingRunner] Phone verification required by Auth for {mask_identifier(self.email)}")
            if on_phone_prompt_needed is None:
                raise RuntimeError("auth_requires_phone")

            phone_result, act_id, _ph = on_phone_prompt_needed()
            last_activation_id = act_id
            phone_continue = codex_oauth._extract_continue_url(phone_result)
            if phone_continue:
                early_callback_url = codex_oauth._follow_login_continue(
                    self.session, phone_continue, state
                ) or early_callback_url
                auth_result = phone_result
        else:
            logger.info(f"[ExistingRunner] Phone step not requested by Auth for {mask_identifier(self.email)}")

        # Step 7: Workspace select -> callback URL
        callback_url = early_callback_url or codex_oauth._select_workspace_and_get_callback(self.session, state)
        code = codex_oauth._extract_code(callback_url, state)

        # Step 8: Token exchange (in memory)
        token_resp = codex_oauth.exchange_codex_token(self.session, code, code_verifier)
        id_claims = codex_oauth._parse_id_token(token_resp.get("id_token", ""))

        return token_resp, id_claims, phone_used, last_activation_id


class _PostAcquireError(Exception):
    """Signals that an error occurred after acquiring a number, holding the activation_id."""
    def __init__(self, message: str, activation_id: str, phone: str, is_unverified_refund: bool = False):
        super().__init__(message)
        self.activation_id = activation_id
        self.phone = phone
        self.is_unverified_refund = is_unverified_refund


def _handle_phone_with_smsfast(
    session: BrowserSession,
    sms_client: SmsFastClient,
    country: str,
    service: str,
    max_price: str | None,
    timeout: int,
    poll_interval: int,
) -> tuple[dict[str, Any], str, str]:
    """
    Purchases ONE number from SMSFast, requests SMS from OpenAI, and validates code.
    Any exception after acquire_number raises _PostAcquireError with activation_id
    so that runner can immediately halt and enter reconciliation_needed state.
    """
    activation_id, phone = sms_client.acquire_number(
        service=service,
        country=country,
        max_price=max_price,
    )

    masked_phone = mask_identifier(phone)
    logger.info(f"[SMSFast] Acquired number {masked_phone} for activation {mask_identifier(activation_id)}")

    # From here on, any exception means number was acquired!
    try:
        # Send SMS from OpenAI
        send_resp = codex_oauth._post_json(
            session,
            "https://auth.openai.com/api/accounts/add-phone/send",
            {"phone_number": f"+{phone}", "channel": "sms"},
            referer="https://auth.openai.com/add-phone",
        )
        send_text = codex_oauth._response_text(send_resp)
        send_reason = codex_oauth._phone_failure_reason(send_text, send_resp.status_code)

        if send_resp.status_code not in (200, 204) or send_reason:
            logger.warning(f"[SMSFast] add-phone/send rejected; cancelling activation {mask_identifier(activation_id)}")
            try:
                sms_client.cancel_and_verify(activation_id)
            except Exception:
                pass
            # ACCESS_CANCEL does not prove refund in current API contract.
            # Fail closed to prevent second purchase without verified refund.
            raise _PostAcquireError("OpenAI rejected phone number", activation_id, phone, is_unverified_refund=True)

        # Notify provider SMS sent
        try:
            sms_client.set_status(activation_id, 1)
        except Exception:
            pass

        # Wait for SMS code up to timeout (180s)
        start_wait = time.time()
        code: str | None = None
        while time.time() - start_wait < timeout:
            status_name, received_code = sms_client.get_status(activation_id)
            if status_name == "STATUS_OK" and received_code:
                code = received_code
                break
            if status_name == "STATUS_CANCEL":
                raise _PostAcquireError("Activation cancelled by provider unexpectedly", activation_id, phone)
            time.sleep(poll_interval)

        if not code:
            logger.warning(f"[SMSFast] Timeout waiting for SMS ({timeout}s). Cancelling activation {mask_identifier(activation_id)}.")
            try:
                sms_client.cancel_and_verify(activation_id)
            except Exception:
                pass
            # Fail closed: cancellation acknowledged, but refund unverified.
            raise _PostAcquireError("SMS timeout; refund cannot be independently verified", activation_id, phone, is_unverified_refund=True)

        # Validate phone OTP with OpenAI
        val_resp = codex_oauth._post_json(
            session,
            "https://auth.openai.com/api/accounts/phone-otp/validate",
            {"code": code},
            referer="https://auth.openai.com/phone-verification",
        )
        if val_resp.status_code not in (200, 204):
            try:
                sms_client.cancel_and_verify(activation_id)
            except Exception:
                pass
            raise _PostAcquireError("OpenAI rejected phone OTP validate", activation_id, phone, is_unverified_refund=True)

        # Complete SMS activation status 6
        try:
            sms_client.set_status(activation_id, 6)
        except Exception:
            pass

        result = codex_oauth._resp_json(val_resp)
        return result, activation_id, phone

    except _PostAcquireError:
        raise
    except Exception as exc:
        # Any unexpected error after acquire_number must be tracked with activation_id
        try:
            sms_client.cancel_and_verify(activation_id)
        except Exception:
            pass
        raise _PostAcquireError(f"Post-acquire error: {type(exc).__name__}", activation_id, phone) from exc


def run_existing_account_oauth(
    email: str,
    password: str,
    proxy: str,
    totp_secret: str | None = None,
    email_otp_callback: Callable[[str, float], str] | None = None,
    smsfast_config: SmsFastRunnerConfig | None = None,
) -> ExistingAccountRunnerResult:
    """
    Main entrypoint for existing account OAuth authorization.

    Guarantees:
    - Never passes secrets via argv/env.
    - Operates purely in-memory: no SQLite writes, no credentials or tokens saved to disk.
    - Explicit proxy required; fail-closed on empty/direct proxy (no direct fallback).
    - Session isolation: each retry / attempt spins up a brand new BrowserSession with unique fingerprint.
    - Phone purchase only when OpenAI explicitly demands phone verification.
    - If ANY exception occurs after acquire_number, status=reconciliation_needed and never buys a second number.
    - ACCESS_CANCEL does not prove refund: halts and does not buy another number.
    - Whitelist error_code and static redacted descriptions only (no raw exception strings).
    - Validates identity: claims email must match requested email and account_id must be present.
    """
    if not proxy or not str(proxy).strip():
        code, msg = _get_static_error("proxy_required")
        return ExistingAccountRunnerResult(
            ok=False,
            status="failed",
            email=mask_identifier(email),
            error_code=code,
            redacted_error=msg,
        )

    if not email or not password:
        code, msg = _get_static_error("missing_credentials")
        return ExistingAccountRunnerResult(
            ok=False,
            status="failed",
            email=mask_identifier(email),
            error_code=code,
            redacted_error=msg,
        )

    max_retries = smsfast_config.max_retries_per_run if smsfast_config else 1
    countries = list(smsfast_config.countries) if smsfast_config else []

    sms_client: SmsFastClient | None = None
    if smsfast_config:
        sms_client = SmsFastClient(
            api_key=smsfast_config.api_key,
            base_url=smsfast_config.base_url,
            timeout=30,
        )

    attempt = 0
    phone_used = False
    last_error_code = "auth_flow_failed"

    while attempt < max_retries:
        attempt += 1
        country = countries[(attempt - 1) % len(countries)] if countries else ""

        try:
            oauth_session = ExistingAccountOAuthSession(
                email=email,
                proxy=proxy,
                password=password,
                totp_secret=totp_secret,
                email_otp_callback=email_otp_callback,
            )
        except ValueError as exc:
            # Proxy configuration invalid / direct connection forbidden
            code, msg = _get_static_error("proxy_configuration_invalid")
            return ExistingAccountRunnerResult(
                ok=False,
                status="failed",
                email=mask_identifier(email),
                error_code=code,
                redacted_error=msg,
                attempts=attempt,
            )

        try:
            def phone_handler():
                if not sms_client or not smsfast_config:
                    raise RuntimeError("auth_requires_phone")
                return _handle_phone_with_smsfast(
                    session=oauth_session.session,
                    sms_client=sms_client,
                    country=country,
                    service=smsfast_config.service,
                    max_price=smsfast_config.max_price,
                    timeout=smsfast_config.timeout,
                    poll_interval=smsfast_config.poll_interval,
                )

            tokens, id_claims, used_phone, _act_id = oauth_session.execute_flow(
                smsfast_config=smsfast_config,
                on_phone_prompt_needed=phone_handler if smsfast_config else None,
            )
            phone_used = phone_used or used_phone

            # Step 9: Validate identity: email must match and account_id must be present
            token_email = (id_claims.get("email") or "").strip().lower()
            requested_email = email.strip().lower()
            if not token_email or token_email != requested_email:
                code, msg = _get_static_error("identity_mismatch")
                return ExistingAccountRunnerResult(
                    ok=False,
                    status="failed",
                    email=mask_identifier(email),
                    error_code=code,
                    redacted_error=msg,
                    attempts=attempt,
                    phone_used=phone_used,
                )

            account_id = id_claims.get("account_id") or ""
            if not account_id:
                code, msg = _get_static_error("missing_account_id")
                return ExistingAccountRunnerResult(
                    ok=False,
                    status="failed",
                    email=mask_identifier(email),
                    error_code=code,
                    redacted_error=msg,
                    attempts=attempt,
                    phone_used=phone_used,
                )

            plan_type = id_claims.get("plan_type") or ""
            storage = codex_oauth.build_codex_storage(tokens, id_claims)

            return ExistingAccountRunnerResult(
                ok=True,
                status="success",
                email=requested_email,
                account_id=account_id,
                plan_type=plan_type,
                tokens=tokens,
                storage=storage,
                attempts=attempt,
                phone_used=phone_used,
            )

        except _PostAcquireError as exc:
            # Critical: Exception occurred AFTER acquire_number.
            # Must NOT buy any second number! Status=reconciliation_needed.
            code = "sms_timeout_unverified_refund" if exc.is_unverified_refund else "sms_order_failed_reconciliation"
            code, msg = _get_static_error(code)
            logger.error(f"[ExistingRunner] Halting on post-acquire error. Activation {mask_identifier(exc.activation_id)} needs reconciliation.")
            return ExistingAccountRunnerResult(
                ok=False,
                status="reconciliation_needed",
                email=mask_identifier(email),
                error_code=code,
                redacted_error=msg,
                attempts=attempt,
                phone_used=True,
                # Secure internal diagnostic state for admin/service reconciliation (masked phone, masked ID)
                reconciliation_data={
                    "activation_id": exc.activation_id,  # Raw ID stored in secure state for reconciliation job
                    "country": country,
                    "attempt": attempt,
                },
            )

        except SmsFastReconciliationNeededError:
            code, msg = _get_static_error("sms_reconciliation_needed")
            return ExistingAccountRunnerResult(
                ok=False,
                status="reconciliation_needed",
                email=mask_identifier(email),
                error_code=code,
                redacted_error=msg,
                attempts=attempt,
                phone_used=True,
                reconciliation_data={"country": country, "attempt": attempt},
            )

        except AccountUnusableError as exc:
            raw_code = getattr(exc, "error_code", "account_deactivated")
            code, msg = _get_static_error(raw_code, fallback_code="account_unusable")
            return ExistingAccountRunnerResult(
                ok=False,
                status="deactivated",
                email=mask_identifier(email),
                error_code=code,
                redacted_error=msg,
                attempts=attempt,
                phone_used=phone_used,
            )

        except SmsFastNoBalanceError:
            code, msg = _get_static_error("smsfast_no_balance")
            return ExistingAccountRunnerResult(
                ok=False,
                status="failed",
                email=mask_identifier(email),
                error_code=code,
                redacted_error=msg,
                attempts=attempt,
                phone_used=True,
            )

        except SmsFastNoNumbersError:
            last_error_code = "smsfast_no_numbers"
            logger.warning(f"[ExistingRunner] No numbers for country {country}. Trying next country if available.")
            continue

        except Exception as exc:
            err_msg_str = str(exc)
            if "auth_requires_mfa" in err_msg_str:
                code, msg = _get_static_error("auth_requires_mfa")
            elif "email_otp_timeout" in err_msg_str:
                code, msg = _get_static_error("email_otp_timeout")
            elif "email_otp_cancelled" in err_msg_str:
                code, msg = _get_static_error("email_otp_cancelled")
            elif "auth_requires_email_otp" in err_msg_str:
                code, msg = _get_static_error("auth_requires_email_otp")
            elif "auth_requires_phone" in err_msg_str:
                code, msg = _get_static_error("auth_requires_phone")
            else:
                code, msg = _get_static_error("auth_flow_failed")

            return ExistingAccountRunnerResult(
                ok=False,
                status="failed",
                email=mask_identifier(email),
                error_code=code,
                redacted_error=msg,
                attempts=attempt,
                phone_used=phone_used,
            )

        finally:
            oauth_session.close()

    code, msg = _get_static_error(last_error_code, fallback_code="max_retries_exceeded")
    return ExistingAccountRunnerResult(
        ok=False,
        status="failed",
        email=mask_identifier(email),
        error_code=code,
        redacted_error=msg,
        attempts=attempt,
        phone_used=phone_used,
    )
