# -*- coding: utf-8 -*-
"""
Tests for SMSFast client, provider integration, and fail-closed reconciliation.
"""
from unittest.mock import MagicMock, patch
import pytest

from core import sms_provider
from core.smsfast_provider import (
    DEFAULT_SMSFAST_BASE_URL,
    DEFAULT_OPENAI_SERVICE,
    DEFAULT_SMS_TIMEOUT,
    SmsFastClient,
    SmsFastError,
    SmsFastNoBalanceError,
    SmsFastNoNumbersError,
    SmsFastReconciliationNeededError,
    SmsFastTimeoutError,
    _mask_identifier,
)


class DummyResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


class DummySession:
    def __init__(self, responses: list[DummyResponse] | None = None):
        self.responses = list(responses or [])
        self.calls = []
        self.closed = False

    def get(self, url, params=None):
        self.calls.append((url, params))
        if not self.responses:
            raise RuntimeError("No more mocked responses in DummySession")
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp

    def close(self):
        self.closed = True


def test_mask_identifier():
    assert _mask_identifier("") == ""
    assert _mask_identifier("12") == "***"
    assert _mask_identifier("1234") == "***"
    assert _mask_identifier("12345") == "12***45"
    assert _mask_identifier("+1234567890") == "+1***90"


def test_smsfast_acquire_number_success():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("ACCESS_NUMBER:987654:16195366483", 200)
    ])

    act_id, phone = client.acquire_number(service="dr", country="10", http=session)
    assert act_id == "987654"
    assert phone == "16195366483"
    assert len(session.calls) == 1
    url, params = session.calls[0]
    assert url == DEFAULT_SMSFAST_BASE_URL
    assert params["api_key"] == "test-key"
    assert params["action"] == "getNumber"
    assert params["service"] == "dr"
    assert params["country"] == "10"


def test_smsfast_purchase_parameters_match_catalog_service_without_operator():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([DummyResponse("ACCESS_NUMBER:987654:521234567890", 200)])

    client.acquire_number(service="dr", country="54", max_price="4000.0", http=session)

    url, params = session.calls[0]
    assert url == DEFAULT_SMSFAST_BASE_URL
    assert params == {
        "api_key": "test-key",
        "action": "getNumber",
        "service": "dr",
        "country": "54",
        "maxPrice": "4000.0",
    }


def test_smsfast_acquire_number_no_numbers():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("NO_NUMBERS", 200)
    ])

    with pytest.raises(SmsFastNoNumbersError) as exc_info:
        client.acquire_number(service="dr", country="10", http=session)
    assert "NO_NUMBERS" in str(exc_info.value)
    assert exc_info.value.reason_code == "smsfast_no_numbers"
    assert [params["action"] for _, params in session.calls] == ["getNumber", "getPrices"]


@pytest.mark.parametrize("price, balance, max_price, expected", [
    (43.16, 100.0, "15", "smsfast_price_limit"),
    (43.16, 20.0, "4000", "smsfast_balance_below_price"),
    (43.16, 100.0, "4000", "smsfast_purchase_refused_with_stock"),
])
def test_smsfast_no_numbers_diagnosis_is_read_only(price, balance, max_price, expected):
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("NO_NUMBERS", 200),
        DummyResponse(f'{{"54":{{"dr":{{"cost":{price},"count":288190}}}}}}', 200),
        DummyResponse(f"ACCESS_BALANCE:{balance}", 200),
    ])

    with pytest.raises(SmsFastNoNumbersError) as exc_info:
        client.acquire_number(service="dr", country="54", max_price=max_price, http=session)

    assert exc_info.value.reason_code == expected
    assert [params["action"] for _, params in session.calls] == ["getNumber", "getPrices", "getBalance"]


def test_smsfast_no_numbers_with_zero_catalog_stock():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("NO_NUMBERS", 200),
        DummyResponse('{"54":{"dr":{"cost":43.16,"count":0}}}', 200),
        DummyResponse("ACCESS_BALANCE:100", 200),
    ])

    with pytest.raises(SmsFastNoNumbersError) as exc_info:
        client.acquire_number(service="dr", country="54", max_price="4000", http=session)

    assert exc_info.value.reason_code == "smsfast_out_of_stock"
    assert [params["action"] for _, params in session.calls] == ["getNumber", "getPrices", "getBalance"]


@pytest.mark.parametrize("prices", ["[]", '{"54":{"dr":null}}', "NO_NUMBERS"])
def test_smsfast_no_numbers_preserved_when_read_only_diagnosis_fails(prices):
    client = SmsFastClient(api_key="test-key")
    session = DummySession([DummyResponse("NO_NUMBERS", 200), DummyResponse(prices, 200)])

    with pytest.raises(SmsFastNoNumbersError) as exc_info:
        client.acquire_number(service="dr", country="54", max_price="4000", http=session)

    assert exc_info.value.reason_code == "smsfast_no_numbers"
    assert [params["action"] for _, params in session.calls] == ["getNumber", "getPrices"]


def test_smsfast_acquire_number_no_balance():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("NO_BALANCE", 200)
    ])

    with pytest.raises(SmsFastNoBalanceError) as exc_info:
        client.acquire_number(service="dr", country="10", http=session)
    assert "NO_BALANCE" in str(exc_info.value)


def test_smsfast_invalid_key():
    client = SmsFastClient(api_key="bad-key")
    session = DummySession([
        DummyResponse("BAD_KEY", 200)
    ])

    with pytest.raises(SmsFastError) as exc_info:
        client.acquire_number(service="dr", country="10", http=session)
    assert "BAD_KEY" in str(exc_info.value)
    # Ensure api key is never in exception text
    assert "bad-key" not in str(exc_info.value)


def test_smsfast_malformed_response():
    client = SmsFastClient(api_key="test-key")
    # Response not starting with ACCESS_NUMBER must raise SmsFastReconciliationNeededError
    session = DummySession([
        DummyResponse("UNKNOWN_FORMAT_ERROR", 200)
    ])

    with pytest.raises(SmsFastReconciliationNeededError) as exc_info:
        client.acquire_number(service="dr", country="10", http=session)
    assert "reconciliation required" in str(exc_info.value).lower()
    # Sensitive raw response must not leak into exception text
    assert "UNKNOWN_FORMAT_ERROR" not in str(exc_info.value)


def test_smsfast_network_ambiguity_on_get_number():
    """Transport ambiguity on getNumber must trigger SmsFastReconciliationNeededError."""
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        ConnectionError("TLS connection reset")
    ])

    with pytest.raises(SmsFastReconciliationNeededError) as exc_info:
        client.acquire_number(service="dr", country="10", http=session)
    assert "reconciliation required" in str(exc_info.value).lower()
    assert "test-key" not in str(exc_info.value)


def test_smsfast_strict_structure_validation():
    """Invalid activation_id or phone digits must fail closed."""
    client = SmsFastClient(api_key="test-key")

    # Non-digit activation ID
    session1 = DummySession([DummyResponse("ACCESS_NUMBER:abc:16195366483", 200)])
    with pytest.raises(SmsFastReconciliationNeededError):
        client.acquire_number(service="dr", country="10", http=session1)

    # Non-digit phone
    session2 = DummySession([DummyResponse("ACCESS_NUMBER:12345:16195abc483", 200)])
    with pytest.raises(SmsFastReconciliationNeededError):
        client.acquire_number(service="dr", country="10", http=session2)

    # Phone too short
    session3 = DummySession([DummyResponse("ACCESS_NUMBER:12345:123", 200)])
    with pytest.raises(SmsFastReconciliationNeededError):
        client.acquire_number(service="dr", country="10", http=session3)


def test_smsfast_wait_for_code_success():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("STATUS_WAIT_CODE", 200),
        DummyResponse("STATUS_OK:492015", 200),
    ])

    with patch("time.sleep", return_value=None):
        code = client.wait_for_code("987654", max_wait=30, poll_interval=1, http=session)
    assert code == "492015"


def test_smsfast_malformed_sms_code():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("STATUS_OK:!!", 200),
    ])

    with patch("time.sleep", return_value=None):
        with pytest.raises(SmsFastError) as exc_info:
            client.wait_for_code("987654", max_wait=30, poll_interval=1, http=session)
        assert "Malformed SMS code" in str(exc_info.value)


def test_smsfast_wait_for_code_timeout():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("STATUS_WAIT_CODE", 200),
        DummyResponse("STATUS_WAIT_CODE", 200),
    ])

    with patch("time.sleep", return_value=None), patch("time.time", side_effect=[0, 10, 200]):
        with pytest.raises(SmsFastTimeoutError):
            client.wait_for_code("987654", max_wait=180, poll_interval=5, http=session)


def test_smsfast_cancel_and_verify_confirmed():
    """Exact ACCESS_CANCEL response confirms cancellation acceptance."""
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("ACCESS_CANCEL", 200)
    ])

    res = client.cancel_and_verify("987654", http=session)
    assert res is True
    assert len(session.calls) == 1
    _, params = session.calls[0]
    assert params["action"] == "setStatus"
    assert params["status"] == "8"
    assert params["id"] == "987654"


def test_smsfast_cancel_and_verify_fail_closed_on_unexpected_response():
    """STATUS_CANCEL or anything other than ACCESS_CANCEL must fail-closed without raw leak."""
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("STATUS_CANCEL:secret_info_12345", 200)
    ])

    with pytest.raises(SmsFastReconciliationNeededError) as exc_info:
        client.cancel_and_verify("987654", http=session)
    assert "reconciliation required" in str(exc_info.value)
    # Ensure sensitive raw payload is NOT in exception string
    assert "secret_info_12345" not in str(exc_info.value)


def test_smsfast_cancel_and_verify_fail_closed_on_network_failure():
    """Network failure during cancellation must fail-closed with reconciliation needed."""
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        TimeoutError("Request timed out")
    ])

    with pytest.raises(SmsFastReconciliationNeededError) as exc_info:
        client.cancel_and_verify("987654", http=session)
    assert "reconciliation required" in str(exc_info.value)


def test_smsfast_get_balance_and_prices():
    client = SmsFastClient(api_key="test-key")
    session = DummySession([
        DummyResponse("ACCESS_BALANCE:150.50", 200),
        DummyResponse('{"10":{"dr":{"5.50":12}}}', 200),
        DummyResponse('{"dr":"42"}', 200),
    ])

    bal = client.get_balance(http=session)
    assert bal == 150.50

    prices = client.get_prices(service="dr", country="10", http=session)
    assert prices["10"]["dr"]["5.50"] == 12

    nums = client.get_numbers_status(country="10", http=session)
    assert nums["dr"] == "42"


def test_sms_provider_smsfast_integration():
    from config import codex as _cfg
    session = DummySession([
        DummyResponse("ACCESS_NUMBER:112233:16195366483", 200),
        DummyResponse("STATUS_WAIT_CODE", 200),
        DummyResponse("STATUS_OK:889900", 200),
        DummyResponse("ACCESS_ACTIVATION", 200),
    ])

    with patch.object(_cfg, "SMS_PROVIDER", "smsfast"), \
         patch.object(_cfg, "SMSFAST_API_KEY", "fast-key"), \
         patch.object(_cfg, "SMSFAST_SERVICE", "dr"), \
         patch.object(_cfg, "SMSFAST_COUNTRY", "10"), \
         patch("time.sleep", return_value=None):

        act_id, phone = sms_provider.acquire_number(http=session)
        assert act_id == "112233"
        assert phone == "16195366483"

        code = sms_provider.wait_for_sms_code(act_id, http=session, max_wait=180, poll_interval=1)
        assert code == "889900"

        sms_provider.complete(act_id, http=session)


def test_sms_provider_smsfast_timeout_cancel_reconciliation():
    from config import codex as _cfg
    session = DummySession([
        DummyResponse("ACCESS_NUMBER:112233:16195366483", 200),
        DummyResponse("STATUS_CANCEL", 200),  # Not ACCESS_CANCEL!
    ])

    with patch.object(_cfg, "SMS_PROVIDER", "smsfast"), \
         patch.object(_cfg, "SMSFAST_API_KEY", "fast-key"):

        act_id, _ = sms_provider.acquire_number(http=session)

        # Cancel should fail-closed because response was STATUS_CANCEL instead of ACCESS_CANCEL
        with pytest.raises(sms_provider.SmsReconciliationNeededError) as exc_info:
            sms_provider.cancel(act_id, http=session, background=False)
        assert "reconciliation" in str(exc_info.value).lower()
