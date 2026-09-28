# -*- coding: utf-8 -*-
"""
Unix Domain Socket IPC Server for existing_account_runner.

Provides a secure, strictly local IPC interface for Sub2API Go backend:
- Unix domain socket with 0600 file permissions and SO_PEERCRED / LOCAL_PEERCRED check.
- Framing: 4-byte big-endian length prefix + UTF-8 JSON payload.
- Enforced request body limit (default 1MB) and execution timeouts.
- Zero credential logging; secrets are read in-memory and discarded.
- Returns OAuth tokens and claims in-memory only to the calling local Go backend.
"""
from __future__ import annotations

import json
import argparse
import logging
import os
import socket
import stat
import struct
import sys
import threading
import signal
from typing import Any, Callable

from core.existing_account_runner import (
    ExistingAccountRunnerResult,
    SmsFastRunnerConfig,
    run_existing_account_oauth,
)

logger = logging.getLogger(__name__)

# Maximum allowed JSON message size (1 MiB)
MAX_MESSAGE_BYTES = 1024 * 1024

# Enforce a generous IPC timeout (10 minutes) so that OAuth (30s) + SMS timeout (180s) * retries (up to 3)
# never get abruptly severed by the socket transport, causing an unverified SMS order.
DEFAULT_IPC_TIMEOUT = 600.0


def get_peer_uid(sock: socket.socket) -> int:
    """
    Returns the UID of the connected peer on Unix platforms.
    Supports Linux (SO_PEERCRED) and macOS/BSD (LOCAL_PEERCRED / getpeereid).
    """
    # 1. Native getpeereid if available (Python 3.12+ or some BSD systems)
    if hasattr(sock, "getpeereid"):
        try:
            return sock.getpeereid()[0]
        except (AttributeError, OSError):
            pass

    # 2. Linux SO_PEERCRED
    if hasattr(socket, "SO_PEERCRED"):
        try:
            # struct ucred { pid_t pid; uid_t uid; gid_t gid; };
            # Typically 3 integers (12 bytes)
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            return uid
        except (OSError, struct.error):
            pass

    # 3. macOS / BSD LOCAL_PEERCRED
    # On macOS, LOCAL_PEERCRED is socket level 0 (SOL_LOCAL) with value 0x001
    SOL_LOCAL = getattr(socket, "SOL_LOCAL", 0)
    LOCAL_PEERCRED = 0x001
    try:
        # struct xucred on Darwin: cr_version(4), cr_uid(4), cr_ngroups(2), cr_groups(16*4)
        xucred_fmt = "2I h 16I"
        creds = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, struct.calcsize(xucred_fmt))
        _version, uid, _ngroups, *_ = struct.unpack(xucred_fmt, creds)
        return uid
    except (OSError, struct.error):
        pass

    # Fallback if peer creds cannot be queried via socket option:
    # on platforms where socket option is unsupported, return -1.
    return -1


def read_exact(sock: socket.socket, length: int) -> bytes:
    """Reads exactly length bytes from socket or raises EOFError."""
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise EOFError("Connection closed before reading required bytes")
        buf.extend(chunk)
    return bytes(buf)


def read_framed_json(sock: socket.socket, max_bytes: int = MAX_MESSAGE_BYTES) -> dict[str, Any]:
    """Reads length-prefixed JSON message (4 bytes big-endian unsigned int + JSON data)."""
    header = read_exact(sock, 4)
    msg_len = struct.unpack("!I", header)[0]
    if msg_len == 0:
        raise ValueError("Empty message received")
    if msg_len > max_bytes:
        raise ValueError(f"Message size {msg_len} exceeds max allowed {max_bytes} bytes")
    data = read_exact(sock, msg_len)
    return json.loads(data.decode("utf-8"))


def write_framed_json(sock: socket.socket, payload: dict[str, Any], max_bytes: int = MAX_MESSAGE_BYTES):
    """Encodes and writes length-prefixed JSON message."""
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(data) > max_bytes:
        raise ValueError(f"Response size {len(data)} exceeds max allowed {max_bytes} bytes")
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def handle_runner_request(
    req: dict[str, Any],
    runner_fn: Callable[..., ExistingAccountRunnerResult] = run_existing_account_oauth,
    client_sock: socket.socket | None = None,
) -> dict[str, Any]:
    """
    Processes an IPC request dict and returns a serializable response dict.
    Strictly scrubs sensitive arguments from logs.
    If client_sock is provided and email_otp_callback is needed, executes an interactive
    in-band challenge prompt/response over the existing verified socket connection.
    """
    action = req.get("action", "")
    if action == "ping":
        return {"ok": True, "status": "pong"}

    if action != "run_existing_oauth":
        return {
            "ok": False,
            "status": "failed",
            "error_code": "unknown_action",
            "redacted_error": "Unsupported runner action",
        }

    email = req.get("email", "")
    password = req.get("password", "")
    proxy = req.get("proxy", "")
    totp_secret = req.get("totp_secret")
    email_otp_mode = req.get("email_otp_mode", "manual")
    smsfast_raw = req.get("smsfast_config")

    smsfast_cfg: SmsFastRunnerConfig | None = None
    if smsfast_raw and isinstance(smsfast_raw, dict):
        try:
            smsfast_cfg = SmsFastRunnerConfig(
                api_key=smsfast_raw.get("api_key", ""),
                service=smsfast_raw.get("service", ""),
                countries=smsfast_raw.get("countries", []),
                base_url=smsfast_raw.get("base_url", "https://smsfastapi.com/stubs/handler_api.php"),
                max_price=str(smsfast_raw["max_price"]) if smsfast_raw.get("max_price") is not None else None,
                timeout=int(smsfast_raw.get("timeout", 180)),
                poll_interval=int(smsfast_raw.get("poll_interval", 5)),
                max_retries_per_run=int(smsfast_raw.get("max_retries_per_run", 3)),
            )
        except Exception:
            return {
                "ok": False,
                "status": "failed",
                "error_code": "invalid_smsfast_config",
                "redacted_error": "Invalid SMSFast configuration",
            }

    # Setup email OTP callback if manual OTP over IPC is supported and socket is available
    email_otp_cb = None
    if client_sock is not None and email_otp_mode == "manual":
        def _ipc_email_otp_callback(cb_email: str, after_ts: float) -> str:
            # 1. Send challenge prompt event (NO SECRETS: password/totp/tokens omitted)
            prompt_msg = {
                "event": "email_otp_prompt",
                "email": cb_email,
                "prompt_after_ts": after_ts,
            }
            write_framed_json(client_sock, prompt_msg)

            # 2. Wait for single-use OTP response from Go backend
            reply = read_framed_json(client_sock)
            reply_action = reply.get("action", "")
            if reply_action == "submit_email_otp":
                code = str(reply.get("code", "")).strip()
                if not code:
                    raise RuntimeError("email_otp_cancelled")
                return code
            elif reply_action == "cancel_email_otp":
                raise RuntimeError("email_otp_cancelled")
            else:
                raise RuntimeError("email_otp_cancelled")

        email_otp_cb = _ipc_email_otp_callback

    res = runner_fn(
        email=email,
        password=password,
        proxy=proxy,
        totp_secret=totp_secret,
        email_otp_callback=email_otp_cb,
        smsfast_config=smsfast_cfg,
    )

    resp: dict[str, Any] = {
        "ok": res.ok,
        "status": res.status,
        "email": res.email,
        "account_id": res.account_id,
        "plan_type": res.plan_type,
        "tokens": res.tokens,
        "storage": res.storage,
        "error_code": res.error_code,
        "redacted_error": res.redacted_error,
        "attempts": res.attempts,
        "phone_used": res.phone_used,
        "reconciliation_data": res.reconciliation_data,
    }
    return resp


class ExistingAccountIPCDaemon:
    """
    Unix Domain Socket daemon serving existing_account_runner requests.
    Enforces local uid checking and secure socket file permissions (0600).
    """

    def __init__(
        self,
        socket_path: str,
        runner_fn: Callable[..., ExistingAccountRunnerResult] = run_existing_account_oauth,
        enforce_peer_uid: bool = True,
    ):
        self.socket_path = socket_path
        self.runner_fn = runner_fn
        self.enforce_peer_uid = enforce_peer_uid
        self._server_sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._clients: set[threading.Thread] = set()
        self._clients_lock = threading.Lock()

    def start(self):
        dir_path = os.path.dirname(os.path.abspath(self.socket_path))
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, mode=0o700, exist_ok=True)
        directory = os.stat(dir_path)
        if directory.st_uid != os.getuid() or directory.st_mode & 0o077:
            raise PermissionError("IPC socket directory must be private and owned by this user")
        if os.path.lexists(self.socket_path):
            existing = os.lstat(self.socket_path)
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
                raise PermissionError("IPC socket path is not an owned socket")
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.5)
                probe.connect(self.socket_path)
            except (ConnectionRefusedError, FileNotFoundError):
                os.unlink(self.socket_path)
            else:
                raise RuntimeError("IPC socket is already in use")
            finally:
                probe.close()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.socket_path)
        # Strictly set 0600 permissions
        os.chmod(self.socket_path, 0o600)
        bound = os.lstat(self.socket_path)
        self._socket_identity = (bound.st_dev, bound.st_ino)

        sock.listen(16)
        sock.settimeout(1.0)
        self._server_sock = sock
        self._stop_event.clear()

        self._worker_thread = threading.Thread(target=self._serve_loop, daemon=True, name="IPCServer")
        self._worker_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)
        # Let active OAuth/SMS requests finish and report their state before exit.
        while True:
            with self._clients_lock:
                active = list(self._clients)
            if not active:
                break
            for thread in active:
                thread.join()
        if os.path.lexists(self.socket_path):
            try:
                current = os.lstat(self.socket_path)
                if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == self._socket_identity:
                    os.unlink(self.socket_path)
            except OSError:
                pass
        self._socket_identity = None

    def _serve_loop(self):
        while not self._stop_event.is_set():
            try:
                client_sock, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=False)
            with self._clients_lock:
                self._clients.add(t)
            t.start()

    def _handle_client(self, client_sock: socket.socket):
        try:
            client_sock.settimeout(DEFAULT_IPC_TIMEOUT)
            if self.enforce_peer_uid:
                current_uid = os.getuid()
                peer_uid = get_peer_uid(client_sock)
                # Unknown credentials must not silently authorize a connection.
                if peer_uid != current_uid:
                    logger.error(f"[IPC] Peer UID mismatch: expected {current_uid}, got {peer_uid}. Rejecting.")
                    client_sock.close()
                    return

            req = read_framed_json(client_sock)
            resp = handle_runner_request(req, runner_fn=self.runner_fn, client_sock=client_sock)
            write_framed_json(client_sock, resp)
        except Exception as exc:
            try:
                err_resp = {
                    "ok": False,
                    "status": "failed",
                    "error_code": "ipc_error",
                    "redacted_error": f"IPC error: {type(exc).__name__}",
                }
                write_framed_json(client_sock, err_resp)
            except Exception:
                pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            with self._clients_lock:
                self._clients.discard(threading.current_thread())


def main():
    parser = argparse.ArgumentParser(description="Local Account Manager IPC runner")
    parser.add_argument("--socket", required=True, help="Path inside a private (0700) directory")
    args = parser.parse_args()
    daemon = ExistingAccountIPCDaemon(args.socket)
    daemon.start()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    try:
        stopped.wait()
    finally:
        daemon.stop()


if __name__ == "__main__":
    main()
