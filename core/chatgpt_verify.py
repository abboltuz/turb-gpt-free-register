# -*- coding: utf-8 -*-
"""
Post-OAuth ChatGPT verification: one message + assistant reply as account proof.

Runs AFTER the OAuth login on the same authenticated BrowserSession and BEFORE
any account record is created. A single minimal message is sent through
ChatGPT's own backend API; only the fact of the reply (never its content) is
recorded. As a post-OAuth step this is a verification gate, not warming: it
only permits or blocks account creation. The same message round-trip is also
reused by core.chat_warmup BEFORE OAuth as account warm-up, which
empirically makes the later verification SMS deliverable.

Outcomes:
  - ok: assistant reply received -> {"conversation_id": ..., "reply_chars": N}
  - AccountUnusableError: provider explicitly reports a dead account code.
  - ChatVerifyUnavailableError: transport / challenge / timeout. Honest
    unknown: fail closed, operator decides. Never reported as "dead".
"""
import json
import logging
import time
import uuid

from core.openai_auth import (
    AccountUnusableError,
    detect_account_unusable_response_body,
    detect_account_unusable_text,
)

logger = logging.getLogger(__name__)

CHATGPT_BASE = "https://chatgpt.com"
VERIFY_TEXT = "ping"
NAV_TIMEOUT = 20
SEND_TIMEOUT = 30
REPLY_TIMEOUT = 120
POLL_INTERVAL = 5


class ChatVerifyUnavailableError(RuntimeError):
    """ChatGPT verification could not be completed (network/challenge/timeout)."""


def _mask_email(email: str) -> str:
    s = str(email or "").strip()
    if "@" in s:
        local, _, domain = s.partition("@")
        return (local[:2] + "***@" + domain) if len(local) > 2 else "***@" + domain
    return (s[:2] + "***") if len(s) > 2 else "***"


def _raise_if_dead(body_text: str, where: str) -> None:
    """Raise AccountUnusableError only on explicit provider dead-account verdicts."""
    code = detect_account_unusable_response_body(body_text or "")
    if not code:
        code = detect_account_unusable_text(body_text or "")
    if code:
        raise AccountUnusableError(
            f"ChatGPT verification reports unusable account ({code}) at {where}",
            error_code=code,
        )


def _authed_chat_session(session, email: str) -> str:
    """Establish chatgpt.com SSO cookies on the OAuth-authenticated session.

    Returns the ChatGPT user access token. Raises ChatVerifyUnavailableError
    on any transport/challenge/empty-session outcome (never "dead").
    """
    masked = _mask_email(email)
    try:
        nav = session.get(
            CHATGPT_BASE + "/",
            headers=session.get_chatgpt_navigate_headers(referer="", user_initiated=True),
            allow_redirects=True,
            timeout=NAV_TIMEOUT,
        )
    except Exception as exc:
        raise ChatVerifyUnavailableError(f"chatgpt.com navigation failed: {type(exc).__name__}")
    if getattr(nav, "status_code", 0) != 200:
        raise ChatVerifyUnavailableError(
            f"chatgpt.com navigation status={getattr(nav, 'status_code', '?')}"
        )

    try:
        resp = session.get(
            CHATGPT_BASE + "/api/auth/session",
            headers=session.get_nextauth_headers(referer=CHATGPT_BASE + "/"),
            timeout=NAV_TIMEOUT,
        )
    except Exception as exc:
        raise ChatVerifyUnavailableError(f"auth session request failed: {type(exc).__name__}")
    if getattr(resp, "status_code", 0) != 200:
        raise ChatVerifyUnavailableError(
            f"auth session status={getattr(resp, 'status_code', '?')}"
        )
    try:
        data = resp.json()
    except Exception:
        raise ChatVerifyUnavailableError("auth session is not JSON")
    if not isinstance(data, dict):
        raise ChatVerifyUnavailableError("auth session malformed")

    access_token = str(data.get("accessToken") or "")
    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    session_email = str(user.get("email") or "").strip().lower()
    if not access_token or not session_email:
        raise ChatVerifyUnavailableError("no authenticated ChatGPT session")
    if session_email != str(email or "").strip().lower():
        raise ChatVerifyUnavailableError("chat session identity mismatch")
    logger.info("[ChatVerify] ChatGPT session ok for %s", masked)
    return access_token


def _send_message(session, access_token: str) -> str:
    """POST one minimal message. Returns conversation_id or raises."""
    headers = dict(session._get_common_headers()) if hasattr(session, "_get_common_headers") else {}
    headers.update({
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Origin": CHATGPT_BASE,
        "Referer": CHATGPT_BASE + "/",
    })
    try:
        device_id = getattr(session, "device_id", "")
        if device_id:
            headers["oai-device-id"] = str(device_id)
    except Exception:
        pass

    payload = {
        "action": "next",
        "messages": [{
            "id": str(uuid.uuid4()),
            "author": {"role": "user"},
            "content": {"content_type": "text", "parts": [VERIFY_TEXT]},
            "metadata": {},
        }],
        "model": "auto",
        "parent_message_id": str(uuid.uuid4()),
        "timezone_offset_min": 0,
    }
    try:
        resp = session.post(
            CHATGPT_BASE + "/backend-api/conversation",
            headers=headers,
            data=json.dumps(payload),
            timeout=SEND_TIMEOUT,
        )
    except Exception as exc:
        raise ChatVerifyUnavailableError(f"conversation send failed: {type(exc).__name__}")

    body = getattr(resp, "text", "") or ""
    if getattr(resp, "status_code", 0) != 200:
        _raise_if_dead(body, "conversation send")
        raise ChatVerifyUnavailableError(
            f"conversation send status={getattr(resp, 'status_code', '?')}"
        )
    conversation_id = ""
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        chunk = line[5:].strip()
        if not chunk or chunk == "[DONE]":
            continue
        try:
            event = json.loads(chunk)
        except Exception:
            continue
        conversation_id = str(event.get("conversation_id") or "")
        if conversation_id:
            break
    if not conversation_id:
        _raise_if_dead(body, "conversation send")
        raise ChatVerifyUnavailableError("no conversation_id in send response")
    return conversation_id


def _assistant_reply_chars(session, access_token: str, conversation_id: str,
                           reply_timeout: float, poll_interval: float) -> int:
    """Poll the conversation until an assistant message carries text."""
    headers = dict(session._get_common_headers()) if hasattr(session, "_get_common_headers") else {}
    headers.update({
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Origin": CHATGPT_BASE,
        "Referer": CHATGPT_BASE + "/",
    })
    deadline = time.time() + max(0.0, reply_timeout)
    while True:
        if time.time() >= deadline:
            raise ChatVerifyUnavailableError("assistant reply timeout")
        try:
            resp = session.get(
                f"{CHATGPT_BASE}/backend-api/conversation/{conversation_id}",
                headers=headers,
                timeout=SEND_TIMEOUT,
            )
        except Exception:
            time.sleep(poll_interval)
            continue
        body = getattr(resp, "text", "") or ""
        if getattr(resp, "status_code", 0) != 200:
            try:
                _raise_if_dead(body, "conversation poll")
            except AccountUnusableError:
                raise
            time.sleep(poll_interval)
            continue
        try:
            data = json.loads(body)
        except Exception:
            time.sleep(poll_interval)
            continue
        mapping = data.get("mapping") if isinstance(data, dict) else None
        if isinstance(mapping, dict):
            for node in mapping.values():
                if not isinstance(node, dict):
                    continue
                msg = node.get("message") if isinstance(node.get("message"), dict) else None
                if not msg:
                    continue
                author = msg.get("author") if isinstance(msg.get("author"), dict) else {}
                if author.get("role") != "assistant":
                    continue
                content = msg.get("content") if isinstance(msg.get("content"), dict) else {}
                parts = content.get("parts")
                text = "".join(p for p in parts if isinstance(p, str)) if isinstance(parts, list) else ""
                if text.strip():
                    return len(text)
        time.sleep(poll_interval)


def verify_chat_reply(session, email: str, *, reply_timeout: float = REPLY_TIMEOUT,
                      poll_interval: float = POLL_INTERVAL) -> dict:
    """Send one minimal message as the account and wait for the assistant reply.

    Message content and reply content are never logged. Returns
    {"conversation_id": ..., "reply_chars": N} or raises AccountUnusableError
    (explicit dead verdict) / ChatVerifyUnavailableError (honest unknown).
    """
    masked = _mask_email(email)
    logger.info("[ChatVerify] verifying ChatGPT round-trip for %s", masked)
    started = time.time()
    access_token = _authed_chat_session(session, email)
    conversation_id = _send_message(session, access_token)
    reply_chars = _assistant_reply_chars(
        session, access_token, conversation_id,
        reply_timeout=reply_timeout, poll_interval=poll_interval,
    )
    logger.info(
        "[ChatVerify] reply received for %s: reply_chars=%d elapsed=%.1fs",
        masked, reply_chars, time.time() - started,
    )
    return {"conversation_id": conversation_id, "reply_chars": reply_chars}
