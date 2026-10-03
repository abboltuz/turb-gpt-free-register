# -*- coding: utf-8 -*-
"""
Pre-OAuth ChatGPT web warm-up for Sub2API Account Manager imports.

Empirically, a fresh account that never chatted on chatgpt.com does not
receive the verification SMS during Codex OAuth (the provider accepts the
number but no SMS arrives). Warming the account first — real browser login
on chatgpt.com followed by one minimal message + assistant reply — makes
the subsequent Codex authorization deliver the SMS.

Runs BEFORE any Codex OAuth attempt and therefore BEFORE any SMSFast
purchase: a warm-up failure costs nothing and fails the job closed with
a whitelisted error code.

Never logs message/reply content, passwords, TOTPs, OTP codes or cookies.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable

logger = logging.getLogger(__name__)

LOGIN_URL = "https://chatgpt.com/auth/login"
LOGIN_TIMEOUT = 150
CHAT_UI_TIMEOUT = 30

EMAIL_SELECTORS = [
    'input[type="email"]',
    'input[name="username"]',
    'input[name="email"]',
    'input[type="text"]',
]
PASSWORD_SELECTORS = [
    'input[type="password"]',
]
CODE_SELECTORS = [
    'input[inputmode="numeric"]',
    'input[name="code"]',
    'input[autocomplete="one-time-code"]',
]
CONTINUE_TEXTS = ("continue", "next", "verify", "confirm", "log in", "sign in")


def _mask_email(email: str | None) -> str:
    s = str(email or "").strip()
    if "@" in s:
        local, _, domain = s.partition("@")
        return (local[:2] + "***@" + domain) if len(local) > 2 else "***@" + domain
    return (s[:2] + "***") if len(s) > 2 else "***"


class ChatWarmupUnavailableError(RuntimeError):
    """Warm-up could not be completed (honest unknown, fail closed)."""


def _fill_box(page, selectors: list[str], value: str, *, timeout_ms: int = 15000,
              label: str = "input") -> None:
    """Fill the first visible input, waiting until it is editable.

    The login pages hydrate via React: an input can be visible but
    temporarily readonly/disabled. Wait for editable, click to focus,
    then fill; fall back to keyboard typing. Raises
    ChatWarmupUnavailableError when nothing becomes fillable.
    """
    box = _first_visible_locator(page, selectors, timeout_ms=2000)
    if box is None:
        raise ChatWarmupUnavailableError(f"{label}: input not found{page_snapshot(page)}")
    deadline = time.time() + max(1.0, timeout_ms / 1000.0)
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            if box.is_editable():
                try:
                    box.click(timeout=3000)
                except Exception:
                    pass
                time.sleep(0.5)
                try:
                    box.fill(value, timeout=8000)
                    return
                except Exception as exc:
                    last_exc = exc
                    try:
                        box.click(timeout=3000)
                        time.sleep(0.3)
                        page.keyboard.type(value, delay=20)
                        return
                    except Exception as exc2:
                        last_exc = exc2
        except Exception as exc:
            last_exc = exc
        time.sleep(1.0)
    raise ChatWarmupUnavailableError(
        f"{label}: input not fillable: "
        f"{type(last_exc).__name__ if last_exc else 'timeout'}{page_snapshot(page)}"
    )


def page_snapshot(page) -> str:
    """One-line safe page summary: title, URL path and input states only."""
    try:
        title = str(page.title() or "")[:60]
    except Exception:
        title = "?"
    try:
        url = str(page.url or "")[:100]
    except Exception:
        url = "?"
    parts = []
    for name, sels in (("email", EMAIL_SELECTORS), ("pwd", PASSWORD_SELECTORS), ("code", CODE_SELECTORS)):
        try:
            locs = page.locator(sels[0]).all()
            states = []
            for loc in locs[:3]:
                try:
                    states.append(f"v={int(loc.is_visible())}e={int(loc.is_enabled())}w={int(loc.is_editable())}")
                except Exception:
                    states.append("?")
            parts.append(f"{name}n={len(locs)}[{','.join(states)}]")
        except Exception:
            parts.append(f"{name}n=?")
    return f" | title={title} url={url} {' '.join(parts)}"


def _first_visible_locator(page, selectors: list[str], timeout_ms: int = 3000):
    """Return a locator for the first selector that becomes visible, else None."""
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            loc.wait_for(state="visible", timeout=timeout_ms)
            return loc
        except Exception:
            continue
    return None


def _click_continue(page) -> bool:
    """Click a Continue/Verify-style button; True if one was clicked."""
    try:
        buttons = page.locator('button[type="submit"], button').all()
    except Exception:
        return False
    for btn in buttons:
        try:
            if not btn.is_visible():
                continue
            text = (btn.inner_text(timeout=1000) or "").strip().lower()
            if text in CONTINUE_TEXTS:
                btn.click(timeout=5000)
                return True
        except Exception:
            continue
    return False


def _chat_ui_present(page) -> bool:
    """True when the logged-in chat composer is on screen."""
    for sel in ('#prompt-textarea', 'textarea[data-testid]', 'div[contenteditable="true"]', "textarea"):
        try:
            if page.locator(sel).first.is_visible():
                return True
        except Exception:
            continue
    return False


def _settle_challenge(page, timeout_s: int = 30) -> None:
    """Give a Cloudflare Turnstile checkbox a chance to clear."""
    deadline = time.time() + max(0, timeout_s)
    while time.time() < deadline:
        if _first_visible_locator(page, EMAIL_SELECTORS, timeout_ms=2000):
            return
        if _chat_ui_present(page):
            return
        try:
            page.keyboard.press("Tab")
            time.sleep(0.3)
            page.keyboard.press("Space")
        except Exception:
            pass
        time.sleep(2.0)


def _web_login(page, email: str, password: str, totp_secret: str | None,
               email_otp_callback: Callable[[str, float], str] | None) -> None:
    """Full web login on chatgpt.com. Raises ChatWarmupUnavailableError."""
    masked = _mask_email(email)
    try:
        page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:
        raise ChatWarmupUnavailableError(f"login page navigation failed: {type(exc).__name__}")
    logger.info("[ChatWarmup] login page loaded for %s", masked)
    _settle_challenge(page)

    deadline = time.time() + LOGIN_TIMEOUT
    otp_after_ts = time.time()
    password_done = False
    last_stage = ""
    while time.time() < deadline:
        if _chat_ui_present(page):
            logger.info("[ChatWarmup] already logged in for %s", masked)
            return
        email_box = _first_visible_locator(page, EMAIL_SELECTORS, timeout_ms=2000)
        if email_box and not password_done:
            logger.info("[ChatWarmup] stage=email for %s", masked)
            last_stage = "email"
            _fill_box(page, EMAIL_SELECTORS, email, label="email")
            time.sleep(1.0)
            if not _click_continue(page):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
            time.sleep(3.0)
            continue
        pwd_box = _first_visible_locator(page, PASSWORD_SELECTORS, timeout_ms=2000)
        if pwd_box:
            if last_stage != "password":
                logger.info("[ChatWarmup] stage=password for %s", masked)
                last_stage = "password"
            try:
                _fill_box(page, PASSWORD_SELECTORS, password, label="password")
            except Exception as exc:
                raise ChatWarmupUnavailableError(f"password fill failed: {type(exc).__name__}")
            time.sleep(1.0)
            if not _click_continue(page):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
            password_done = True
            # Optional TOTP on the same or next screen.
            if totp_secret:
                try:
                    import pyotp
                    if _first_visible_locator(page, CODE_SELECTORS, timeout_ms=12000):
                        _fill_box(page, CODE_SELECTORS, pyotp.TOTP(str(totp_secret).strip()).now(),
                                  timeout_ms=20000, label="totp")
                        time.sleep(1.0)
                        if not _click_continue(page):
                            try:
                                page.keyboard.press("Enter")
                            except Exception:
                                pass
                except ChatWarmupUnavailableError:
                    raise
                except Exception as exc:
                    raise ChatWarmupUnavailableError(f"TOTP fill failed: {type(exc).__name__}")
            time.sleep(3.0)
            continue
        code_box = _first_visible_locator(page, CODE_SELECTORS, timeout_ms=2000)
        if code_box and password_done:
            if last_stage != "code":
                logger.info("[ChatWarmup] stage=code for %s", masked)
                last_stage = "code"
            if email_otp_callback is None:
                raise ChatWarmupUnavailableError("email OTP required but no callback")
            try:
                otp = email_otp_callback(email, otp_after_ts)
            except Exception as exc:
                raise ChatWarmupUnavailableError(f"email OTP callback failed: {type(exc).__name__}")
            try:
                _fill_box(page, CODE_SELECTORS, str(otp).strip(), label="email-otp")
            except Exception as exc:
                raise ChatWarmupUnavailableError(f"OTP fill failed: {type(exc).__name__}")
            time.sleep(1.0)
            if not _click_continue(page):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
            time.sleep(3.0)
            continue
        time.sleep(2.0)
    raise ChatWarmupUnavailableError("login did not complete in time")


def _sync_cookies_to_session(driver, session) -> None:
    """Copy browser cookies + UA into a protocol session (no values logged)."""
    try:
        cookies = driver.context.cookies()
    except Exception as exc:
        raise ChatWarmupUnavailableError(f"cookie export failed: {type(exc).__name__}")
    count = 0
    for c in cookies or []:
        try:
            domain = str(c.get("domain", "") or "")
            if domain.startswith("."):
                domain = domain[1:]
            session.session.cookies.set(c["name"], c["value"], domain=domain)
            count += 1
        except Exception:
            continue
    try:
        ua = driver.page.evaluate("navigator.userAgent")
    except Exception:
        ua = ""
    if ua:
        try:
            session.browser_profile["user_agent"] = str(ua)
        except Exception:
            pass
    logger.info("[ChatWarmup] synced %d cookies into protocol session", count)


def warmup_chat_before_oauth(
    email: str,
    password: str,
    proxy: str,
    totp_secret: str | None = None,
    email_otp_callback: Callable[[str, float], str] | None = None,
) -> dict[str, Any]:
    """Browser login on chatgpt.com + one message round-trip.

    Returns {"reply_chars": N}. Raises ChatWarmupUnavailableError on any
    failure. Makes no purchase and leaves no account record behind.
    """
    from core.session import BrowserSession
    from core import chatgpt_verify
    from config import cloakbrowser as cloak_cfg

    masked = _mask_email(email)
    logger.info("[ChatWarmup] starting web warm-up for %s", masked)

    # Servers have no display; force headless for the warm-up browser only.
    prev_headless = bool(getattr(cloak_cfg, "CLOAK_HEADLESS", False))
    cloak_cfg.CLOAK_HEADLESS = True
    driver = None
    try:
        from core.cloakbrowser_driver import build_cloak_driver
        logger.info("[ChatWarmup] launching browser for %s", masked)
        driver, _ = build_cloak_driver(proxy=proxy)
        logger.info("[ChatWarmup] browser ready, opening login for %s", masked)
        _web_login(driver.page, email, password, totp_secret, email_otp_callback)
        logger.info("[ChatWarmup] web login done for %s, waiting for chat UI", masked)
        try:
            driver.page.wait_for_function(
                "() => !!document.querySelector('#prompt-textarea,textarea,div[contenteditable=\"true\"]')",
                timeout=CHAT_UI_TIMEOUT * 1000,
            )
        except Exception as exc:
            raise ChatWarmupUnavailableError(f"chat UI not ready: {type(exc).__name__}")
        session = BrowserSession(
            proxy=proxy or "",
            fingerprint_seed=f"sub2api-warmup:{str(email).strip().lower()}:{uuid.uuid4()}",
            detect_exit_geo=False,
        )
        try:
            _sync_cookies_to_session(driver, session)
            proof = chatgpt_verify.verify_chat_reply(session, email)
        finally:
            try:
                session.close()
            except Exception:
                pass
        logger.info("[ChatWarmup] warm-up ok for %s: reply_chars=%d", masked, proof["reply_chars"])
        return proof
    finally:
        cloak_cfg.CLOAK_HEADLESS = prev_headless
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
