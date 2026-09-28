# -*- coding: utf-8 -*-
"""
Tests for phone prompt requirement and fresh OAuth session retry semantics in Codex OAuth flow.
"""
from unittest.mock import MagicMock, patch
import pytest

from core import codex_oauth
from core import sms_provider


def test_phone_prompt_required_to_acquire_number():
    """Numbers should NEVER be acquired unless _is_phone_step is True."""
    # When Auth step is not phone step, sms_provider.acquire_number must NOT be called.
    non_phone_auth_result = {
        "page": {"type": "organization"},
        "continue_url": "https://auth.openai.com/callback",
    }
    assert codex_oauth._is_phone_step(non_phone_auth_result) is False

    phone_auth_result = {
        "page": {"type": "phone-verification"},
    }
    assert codex_oauth._is_phone_step(phone_auth_result) is True


def test_do_phone_verification_stops_on_reconciliation_needed():
    """If cancellation or state cannot be reconciled, do NOT purchase new number."""
    mock_session = MagicMock()
    mock_http = MagicMock()

    with patch.object(sms_provider, "_provider", return_value="smsfast"), \
         patch.object(sms_provider, "_http", return_value=mock_http), \
         patch.object(sms_provider, "acquire_number", return_value=("act_123", "16195366483")), \
         patch.object(codex_oauth, "_post_json", return_value=MagicMock(status_code=400)), \
         patch.object(codex_oauth, "_response_text", return_value='{"error": "invalid_phone"}'), \
         patch.object(sms_provider, "cancel", side_effect=sms_provider.SmsReconciliationNeededError("Not reconciled")):

        with pytest.raises(sms_provider.SmsReconciliationNeededError):
            codex_oauth._do_phone_verification(mock_session)

        # Ensure acquire_number was only called once and not retried blindly
        assert sms_provider.acquire_number.call_count == 1


def test_acquire_number_transport_error_stops_retries_immediately():
    """Transport ambiguity on acquire_number must immediately raise SmsReconciliationNeededError and halt."""
    mock_session = MagicMock()
    mock_http = MagicMock()

    with patch.object(sms_provider, "_provider", return_value="smsfast"), \
         patch.object(sms_provider, "_http", return_value=mock_http), \
         patch.object(sms_provider, "acquire_number", side_effect=sms_provider.SmsReconciliationNeededError("Ambiguous transport")):

        with pytest.raises(sms_provider.SmsReconciliationNeededError):
            codex_oauth._do_phone_verification(mock_session)

        # Exactly 1 call to acquire_number, no second purchase attempted
        assert sms_provider.acquire_number.call_count == 1


def test_phone_masking_in_logs_for_smsfast():
    """Ensure phone numbers are masked when provider is smsfast."""
    assert codex_oauth._mask_phone("16195366483") == "16***83"
    assert codex_oauth._mask_phone("123") == "***"
    assert codex_oauth._mask_phone("") == ""
