# -*- coding: utf-8 -*-
"""
SMSFast 接码平台客户端及适配器。

Официальный контракт handler_api:
  GET https://smsfastapi.com/stubs/handler_api.php
  1) action=getNumber&service=SERVICE&country=COUNTRY[&operator=OPERATOR][&maxPrice=MAXPRICE]
     Успех: ACCESS_NUMBER:ID:NUMBER
     Ошибки: BAD_KEY, NO_BALANCE, NO_NUMBERS, BAD_ACTION, BAD_SERVICE, ERROR_SQL
  2) action=getStatus&id=ID
     Ответ: STATUS_WAIT_CODE | STATUS_CANCEL | STATUS_OK:CODE
  3) action=setStatus&status=STATUS&id=ID
     status=8 (отмена активации с возвратом средств):
     Ответ: ACCESS_CANCEL
     status=6 (успешное завершение):
     Ответ: ACCESS_ACTIVATION
  4) action=getBalance
     Ответ: ACCESS_BALANCE:540

ВАЖНО ПО БЕЗОПАСНОСТИ И FAIL-CLOSED ПРАВИЛАМ:
- Никакие API-ключи, номера телефонов и SMS-коды не выводятся в логах и исключениях.
- Строгий Fail-Closed: ответ ACCESS_CANCEL от setStatus(status=8) подтверждает
  принятие отмены провайдером SMSFast, но контракт не даёт отдельной верификации
  фактического возврата баланса (refund receipt unverified / fail-closed).
- Ответ STATUS_CANCEL от getStatus сам по себе не доказывает отмену с возвратом.
  Любой не подтверждённый точно через ACCESS_CANCEL результат переводит активацию
  в состояние RECONCILIATION_NEEDED, и покупка следующего номера блокируется.
"""
import logging
import math
import time

from curl_cffi.requests import Session as CurlSession

from config import IMPERSONATE

logger = logging.getLogger(__name__)

DEFAULT_SMSFAST_BASE_URL = "https://smsfastapi.com/stubs/handler_api.php"
DEFAULT_OPENAI_SERVICE = "dr"
DEFAULT_SMS_TIMEOUT = 180  # 180 секунд ожидания SMS по ТЗ


class SmsFastError(RuntimeError):
    """Базовая ошибка SMSFast."""


class SmsFastNoBalanceError(SmsFastError):
    """NO_BALANCE (нет средств на аккаунте)."""


class SmsFastNoNumbersError(SmsFastError):
    """NO_NUMBERS for the purchase parameters, optionally classified by read-only checks."""

    def __init__(self, message: str, reason_code: str = "smsfast_no_numbers"):
        super().__init__(message)
        self.reason_code = reason_code


class SmsFastTimeoutError(SmsFastError):
    """Таймаут ожидания SMS кода."""


class SmsFastReconciliationNeededError(SmsFastError):
    """Неоднозначное состояние заказа/отмены; требуется аудит/reconciliation."""


def _mask_identifier(ident: str) -> str:
    """Маскирование ID или номера для безопасного логирования."""
    if not ident:
        return ""
    s = str(ident).strip()
    if len(s) <= 4:
        return "***"
    return s[:2] + "***" + s[-2:]


class SmsFastClient:
    """
    Клиент к API SMSFast.
    Все запросы - GET к https://smsfastapi.com/stubs/handler_api.php
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_SMSFAST_BASE_URL,
        timeout: int = 30,
        impersonate: str = IMPERSONATE,
    ):
        if not api_key:
            raise SmsFastError("SMSFast API key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.impersonate = impersonate

    def _http(self) -> CurlSession:
        s = CurlSession(impersonate=self.impersonate)
        s.timeout = self.timeout
        return s

    def _request(self, params: dict, http: CurlSession | None = None) -> str:
        req_params = {"api_key": self.api_key}
        req_params.update(params)

        own_session = http is None
        session = http or self._http()
        action = params.get("action", "unknown")
        try:
            resp = session.get(self.base_url, params=req_params)
            text = (resp.text or "").strip()
            if resp.status_code != 200:
                # Ни в коем случае не включаем сырой ответ сервера в ошибку
                if action == "getNumber":
                    raise SmsFastReconciliationNeededError(
                        f"SMSFast HTTP {resp.status_code} on action=getNumber; purchase state unknown, reconciliation required"
                    )
                raise SmsFastError(f"SMSFast HTTP {resp.status_code} on action={action}")

            # Проверка стандартных кодов ошибок без утечки чувствительных данных
            if text == "BAD_KEY":
                raise SmsFastError("Invalid SMSFast API key (BAD_KEY)")
            if text == "NO_BALANCE":
                raise SmsFastNoBalanceError("Insufficient balance in SMSFast (NO_BALANCE)")
            if text == "NO_NUMBERS":
                raise SmsFastNoNumbersError("No numbers available in SMSFast (NO_NUMBERS)")
            if text in ("BAD_ACTION", "BAD_SERVICE"):
                raise SmsFastError(f"SMSFast request rejected: {text}")
            if text == "NO_ACTIVATION":
                raise SmsFastError("Activation not found (NO_ACTIVATION)")
            if text == "ERROR_SQL":
                if action == "getNumber":
                    raise SmsFastReconciliationNeededError(
                        "SMSFast server error (ERROR_SQL) on action=getNumber; purchase state unknown, reconciliation required"
                    )
                raise SmsFastError("SMSFast server error (ERROR_SQL)")

            return text
        except (SmsFastError, SmsFastNoBalanceError, SmsFastNoNumbersError, SmsFastReconciliationNeededError):
            raise
        except Exception as e:
            # Безопасное сообщение об ошибке сети без url query параметров (где есть api_key)
            if action == "getNumber":
                # Transport timeout/network failure on getNumber may mean order succeeded on server!
                raise SmsFastReconciliationNeededError(
                    f"SMSFast transport ambiguity on action=getNumber ({type(e).__name__}); reconciliation required"
                )
            raise SmsFastError(f"SMSFast transport error on action={action}: {type(e).__name__}")
        finally:
            if own_session:
                try:
                    session.close()
                except Exception:
                    pass

    def get_balance(self, http: CurlSession | None = None) -> float:
        """
        Запрос баланса:
        action=getBalance
        Ответ: ACCESS_BALANCE:540
        """
        text = self._request({"action": "getBalance"}, http=http)
        if text.startswith("ACCESS_BALANCE:"):
            try:
                val = text.split(":", 1)[1].strip()
                return float(val)
            except ValueError:
                raise SmsFastError("Malformed balance response format")
        raise SmsFastError("Unexpected balance response format")

    def acquire_number(
        self,
        service: str = DEFAULT_OPENAI_SERVICE,
        country: str = "10",
        operator: str | None = None,
        max_price: str | None = None,
        http: CurlSession | None = None,
    ) -> tuple[str, str]:
        """
        Заказ номера:
        action=getNumber&service=SERVICE&country=COUNTRY[&operator=OPERATOR][&maxPrice=MAXPRICE]
        Ответ: ACCESS_NUMBER:ID:NUMBER
        """
        params = {
            "action": "getNumber",
            "service": service,
            "country": str(country),
        }
        if operator:
            params["operator"] = str(operator)
        if max_price:
            params["maxPrice"] = str(max_price)

        try:
            text = self._request(params, http=http)
        except SmsFastNoNumbersError as exc:
            # The stock catalog is not a purchase guarantee. Check the current
            # price and balance *without* placing another order, so the failure
            # can be classified instead of guessed from aggregate stock.
            reason_code = "smsfast_no_numbers"
            try:
                # Match the catalog's getPrices query exactly; filtering by
                # service is optional in the provider contract.
                prices = self.get_prices(country=str(country), http=http)
                offer = prices.get(str(country), {}).get(service, {})
                cost = float(offer["cost"])
                count = int(offer["count"])
                if not math.isfinite(cost) or cost <= 0 or count < 0:
                    raise ValueError("invalid SMSFast offer")
                balance = self.get_balance(http=http)
                if not math.isfinite(balance) or balance < 0:
                    raise ValueError("invalid SMSFast balance")
                limit = float(max_price) if max_price is not None else None
                if limit is not None and not math.isfinite(limit):
                    raise ValueError("invalid SMSFast maxPrice")
                if count == 0:
                    reason_code = "smsfast_out_of_stock"
                else:
                    if limit is not None and cost > limit:
                        reason_code = "smsfast_price_limit"
                    elif balance < cost:
                        reason_code = "smsfast_balance_below_price"
                    else:
                        reason_code = "smsfast_purchase_refused_with_stock"
                logger.warning(
                    "[SMSFast] getNumber=NO_NUMBERS country=%s service=%s max_price=%s price=%s stock=%s balance=%s diagnosis=%s",
                    country, service, limit, cost, count, balance, reason_code,
                )
            except (SmsFastError, AttributeError, KeyError, TypeError, ValueError, OverflowError):
                # A failed read-only check must never turn a definite NO_NUMBERS
                # into an ambiguous purchase or trigger another getNumber.
                logger.warning("[SMSFast] getNumber=NO_NUMBERS country=%s service=%s read_only_diagnosis=unavailable", country, service)
            raise SmsFastNoNumbersError("SMSFast getNumber returned NO_NUMBERS", reason_code=reason_code) from exc
        if not text.startswith("ACCESS_NUMBER:"):
            # Неизвестный ответ на getNumber может означать, что номер куплен, но формат не распознан.
            # Fail closed: требуем reconciliation вместо повторной покупки!
            raise SmsFastReconciliationNeededError(
                "Unexpected getNumber response format; purchase state ambiguous, reconciliation required"
            )
        parts = text.split(":")
        if len(parts) != 3:
            raise SmsFastReconciliationNeededError(
                "Malformed ACCESS_NUMBER structure; activation ID or phone cannot be reliably parsed"
            )

        activation_id = parts[1].strip()
        phone = parts[2].strip()

        # Строгая валидация структуры activation_id (числовое) и phone (числовые цифры от 6 до 16)
        if not activation_id.isdigit():
            raise SmsFastReconciliationNeededError(
                "Malformed activation_id in ACCESS_NUMBER response; reconciliation required"
            )
        if not phone.isdigit() or len(phone) < 6 or len(phone) > 16:
            raise SmsFastReconciliationNeededError(
                "Malformed phone number format in ACCESS_NUMBER response; reconciliation required"
            )

        logger.info(f"[SMSFast] Acquired activation ID={_mask_identifier(activation_id)}")
        return activation_id, phone

    def set_status(
        self,
        activation_id: str,
        status: int,
        http: CurlSession | None = None,
    ) -> str:
        """
        Изменить статус:
        action=setStatus&id=ID&status=STATUS
        Возможные статусы:
          3 - повторная отправка
          6 - завершена (ACCESS_ACTIVATION)
          8 - отменена с возвратом средств (ACCESS_CANCEL)
        """
        params = {
            "action": "setStatus",
            "id": str(activation_id),
            "status": str(status),
        }
        return self._request(params, http=http)

    def get_status(
        self,
        activation_id: str,
        http: CurlSession | None = None,
    ) -> tuple[str, str | None]:
        """
        Получить статус:
        action=getStatus&id=ID
        Ответы:
          STATUS_WAIT_CODE
          STATUS_CANCEL
          STATUS_OK:CODE
        """
        text = self._request({"action": "getStatus", "id": str(activation_id)}, http=http)
        if text.startswith("STATUS_OK:"):
            parts = text.split(":", 1)
            raw_code = parts[1].strip() if len(parts) > 1 else ""
            # Строгая валидация SMS-кода: буквенно-цифровой от 4 до 10 символов, без пробелов
            clean_code = "".join(c for c in raw_code if c.isalnum())
            if not clean_code or len(clean_code) < 4 or len(clean_code) > 10:
                raise SmsFastError("Malformed SMS code in getStatus response")
            return "STATUS_OK", clean_code
        if text in ("STATUS_WAIT_CODE", "STATUS_CANCEL"):
            return text, None
        return "UNKNOWN", None

    def cancel_and_verify(
        self,
        activation_id: str,
        http: CurlSession | None = None,
    ) -> bool:
        """
        Строгий Fail-Closed отмена активации:
        Официальный API возвращает 'ACCESS_CANCEL' на запрос setStatus(id, 8), что подтверждает
        успешный приём отмены сервисом. Однако факт фактического зачисления возврата средств
        внешним API-контрактом отдельно не гарантируется (статус баланса/возврата unknown).
        Поэтому при получении ACCESS_CANCEL отмена считается подтверждённой провайдером.
        Любой другой ответ или сбой транспорта НЕ гарантирует даже отмену, переводит статус
        в RECONCILIATION_NEEDED, и покупка следующего номера блокируется.
        Никакой сырой текст ответа в логи и исключения не включается!
        """
        own_session = http is None
        session = http or self._http()
        masked_id = _mask_identifier(activation_id)
        try:
            resp_text = self.set_status(activation_id, 8, http=session)
            if resp_text == "ACCESS_CANCEL":
                logger.info(
                    f"[SMSFast] Activation {masked_id} cancellation confirmed (ACCESS_CANCEL; refund receipt unverified)"
                )
                return True

            raise SmsFastReconciliationNeededError(
                f"Cancellation of activation {masked_id} returned unexpected response code; reconciliation required"
            )
        except SmsFastReconciliationNeededError:
            raise
        except Exception as e:
            logger.warning(f"[SMSFast] setStatus(8) failed for {masked_id}: {type(e).__name__}")
            raise SmsFastReconciliationNeededError(
                f"Cancellation of activation {masked_id} transport failure; reconciliation required"
            )
        finally:
            if own_session:
                try:
                    session.close()
                except Exception:
                    pass


    def wait_for_code(
        self,
        activation_id: str,
        max_wait: int = DEFAULT_SMS_TIMEOUT,
        poll_interval: int = 5,
        http: CurlSession | None = None,
        check_stop_callback=None,
    ) -> str:
        """
        Опрос getStatus до max_wait (по умолчанию 180с).
        Никаких кодов в логи не пишется!
        """
        own_session = http is None
        session = http or self._http()
        deadline = time.time() + max_wait
        masked_id = _mask_identifier(activation_id)

        try:
            while time.time() < deadline:
                if check_stop_callback:
                    check_stop_callback()

                status, code = self.get_status(activation_id, http=session)
                if status == "STATUS_OK" and code:
                    logger.info(f"[SMSFast] Code received for activation {masked_id}")
                    return code
                if status == "STATUS_CANCEL":
                    raise SmsFastError(f"Activation {masked_id} was cancelled externally")

                time.sleep(poll_interval)

            raise SmsFastTimeoutError(f"Timeout waiting for SMS on activation {masked_id} ({max_wait}s)")
        finally:
            if own_session:
                try:
                    session.close()
                except Exception:
                    pass

    def get_prices(
        self,
        service: str | None = None,
        country: str | None = None,
        http: CurlSession | None = None,
    ) -> dict:
        """
        Запрос всех цен:
        action=getPrices[&service=SERVICE][&country=COUNTRY]
        Ответ: JSON { "Страна": { "Сервис": { "Цена": Количество}}}
        """
        params = {"action": "getPrices"}
        if service:
            params["service"] = str(service)
        if country:
            params["country"] = str(country)
        text = self._request(params, http=http)
        try:
            import json
            return json.loads(text)
        except Exception:
            raise SmsFastError("Malformed getPrices JSON response")

    def get_numbers_status(
        self,
        country: str,
        operator: str | None = None,
        http: CurlSession | None = None,
    ) -> dict:
        """
        Запрос количества доступных номеров:
        action=getNumbersStatus&country=COUNTRY[&operator=OPERATOR]
        Ответ: JSON {"Сервис_0":"Количество"}
        """
        params = {"action": "getNumbersStatus", "country": str(country)}
        if operator:
            params["operator"] = str(operator)
        text = self._request(params, http=http)
        try:
            import json
            return json.loads(text)
        except Exception:
            raise SmsFastError("Malformed getNumbersStatus JSON response")
