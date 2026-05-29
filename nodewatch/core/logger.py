"""
core.logger
===========

Single source of truth for writing events.

Every event is a JSON-line ("jsonl") record. We never lose fields:
adding new fields is free, parsers downstream ignore unknown keys.

Two on-disk streams:

  $LOG_DIR/events.jsonl         -> append-only, one event per line
  $LOG_DIR/sessions/<id>.jsonl  -> per-session log (cheap to tail one source)

The aggregator (sync.aggregator) is the *only* thing that builds
per-IP profiles. Sensors only emit events.

Event schema (minimum fields):

  ts              ISO-8601 with microseconds, UTC
  event_id        uuid4
  session_id      uuid4, sticky per remote source session
  node_name       this machine's friendly id
  sensor_profile  ssh | owa | winserver | meta
  event_type      see EventType
  src_ip
  src_port
  dst_port
  proto           tcp | udp | icmp
  data            free-form dict, event-specific
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# Event type constants. Strings, so they're easy to grep.
class EventType:
    CONNECTION       = "connection"          # raw new connection (any port)
    TCP_PAYLOAD      = "tcp_payload"         # bytes received on a listening port
    TLS_FINGERPRINT  = "tls_fingerprint"     # ja3/ja4 extracted from clienthello
    SSH_FINGERPRINT  = "ssh_fingerprint"     # hassh extracted from kexinit (passive)
    SSH_BANNER       = "ssh_banner"          # remote SSH banner / version
    SSH_AUTH         = "ssh_auth"            # username/password attempt
    SSH_LOGIN_OK     = "ssh_login_ok"        # accepted credential set
    SSH_COMMAND      = "ssh_command"         # command run in fake shell
    SSH_SESSION_END  = "ssh_session_end"
    HTTP_REQUEST     = "http_request"        # any HTTP request to OWA sensor
    HTTP_LOGIN       = "http_login"          # OWA POST creds
    WIN_PROBE        = "win_probe"           # connection to a fake windows port
    WIN_PAYLOAD      = "win_payload"         # bytes captured on a fake windows service
    TELNET_AUTH      = "telnet_auth"         # telnet login attempt (IoT/Mirai)
    TELNET_COMMAND   = "telnet_command"      # command run in fake telnet shell
    TELNET_SESSION_END = "telnet_session_end"
    REDIS_COMMAND    = "redis_command"       # parsed RESP command to fake redis
    DOCKER_API       = "docker_api"          # request to fake Docker Engine API
    DOCKER_CONTAINER_CREATE = "docker_container_create"  # parsed container-create payload
    HEARTBEAT        = "heartbeat"
    NODE_START       = "node_start"


_LOG_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class EventLogger:
    """Thread-safe, fork-safe, append-only event logger."""

    def __init__(self, log_dir: str, node_name: str, sensor_profile: str):
        self.log_dir = Path(log_dir)
        self.session_dir = self.log_dir / "sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.node_name = node_name
        self.sensor_profile = sensor_profile
        self.events_file = self.log_dir / "events.jsonl"

    # ----------------------------------------------------------------- emit
    def emit(
        self,
        event_type: str,
        src_ip: str,
        *,
        src_port: int = 0,
        dst_port: int = 0,
        proto: str = "tcp",
        session_id: Optional[str] = None,
        data: Optional[dict] = None,
        sensor_profile: Optional[str] = None,
    ) -> dict:
        rec = {
            "ts": _now_iso(),
            "event_id": str(uuid.uuid4()),
            "session_id": session_id or "",
            "node_name": self.node_name,
            "sensor_profile": sensor_profile or self.sensor_profile,
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "proto": proto,
            "data": data or {},
        }
        line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False, default=str)
        with _LOG_LOCK:
            # Global stream
            with open(self.events_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            # Per-session stream (only if we have a session)
            if session_id:
                with open(self.session_dir / f"{session_id}.jsonl", "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        return rec

    # ----------------------------------------------------------------- helpers
    def new_session(self) -> str:
        return str(uuid.uuid4())

    def heartbeat(self) -> None:
        self.emit(EventType.HEARTBEAT, src_ip="0.0.0.0",
                  data={"uptime_s": int(time.monotonic())})


# Process-global default logger, lazily configured
_default: Optional[EventLogger] = None


def configure(log_dir: str, node_name: str, sensor_profile: str) -> EventLogger:
    global _default
    _default = EventLogger(log_dir, node_name, sensor_profile)
    return _default


def get() -> EventLogger:
    if _default is None:
        # Fallback so library imports don't crash; you should call configure().
        return EventLogger(
            os.environ.get("HP_LOG_DIR", "/var/log/nodewatch"),
            os.environ.get("HP_NODE_NAME", "unknown"),
            os.environ.get("HP_TYPE", "meta"),
        )
    return _default
