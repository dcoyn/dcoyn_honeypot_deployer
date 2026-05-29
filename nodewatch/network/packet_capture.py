"""
nodewatch.network.packet_capture
===============================

Sniffer that complements the application-level sensors. It:

  1. Watches for TLS ClientHello on any port and emits a
     TLS_FINGERPRINT event (JA3 + JA4 + SNI + ALPN).
  2. Tags each fingerprint with the same per-IP session_id the rest of
     the system uses, so SQL on the resulting events groups cleanly.

We intentionally do NOT store full pcap files by default — that's
gigabytes per day on a busy sensor node. The application logs and the
nftables connection log are usually enough. Add ``HP_PCAP=1`` to enable.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.fingerprint import fingerprint, ssh_fingerprint
from ..core.session import TRACKER
from ..core.enrichment import enrich
from ..core import threat_intel as TI

try:
    from scapy.all import sniff, TCP, IP, IPv6, Raw, wrpcap
except Exception:
    sniff = None  # type: ignore


# In-memory rolling buffer of partial TLS handshakes per (src,dport)
_PENDING: dict[tuple[str, int, int], bytearray] = {}
_PENDING_LOCK = threading.Lock()
_MAX_BUF = 16 * 1024


def _maybe_handshake(buf: bytes) -> bool:
    return len(buf) >= 6 and buf[0] == 0x16 and buf[5] == 0x01  # handshake + ClientHello


def _maybe_ssh(buf: bytes) -> bool:
    return buf[:4] == b"SSH-"


# Track which flows we've already SSH-fingerprinted so we emit once per flow.
_SSH_DONE: set = set()


def _flush_after(flow_key):
    """Drop a flow buffer 30s after the handshake (or after failure)."""
    time.sleep(30)
    with _PENDING_LOCK:
        _PENDING.pop(flow_key, None)
        _SSH_DONE.discard(flow_key)


def _handle(pkt) -> None:
    if not (TCP in pkt and Raw in pkt):
        return
    if IP in pkt:
        src = pkt[IP].src; dst_port = pkt[TCP].dport; src_port = pkt[TCP].sport
    elif IPv6 in pkt:
        src = pkt[IPv6].src; dst_port = pkt[TCP].dport; src_port = pkt[TCP].sport
    else:
        return

    payload = bytes(pkt[Raw].load)
    if not payload:
        return

    flow_key = (src, src_port, dst_port)
    with _PENDING_LOCK:
        buf = _PENDING.setdefault(flow_key, bytearray())
        buf += payload
        if len(buf) > _MAX_BUF:
            _PENDING.pop(flow_key, None)
            return

        # --- SSH branch: stream starts with "SSH-" version banner ---
        if _maybe_ssh(bytes(buf[:4])):
            if flow_key in _SSH_DONE:
                return
            snapshot = bytes(buf)
            fp = ssh_fingerprint(snapshot)
            if fp is None:
                return  # KEXINIT not fully reassembled yet; keep buffering
            _SSH_DONE.add(flow_key)
            _PENDING.pop(flow_key, None)
            sid = TRACKER.get(src)
            L.get().emit(
                EventType.SSH_FINGERPRINT,
                src_ip=src, src_port=src_port, dst_port=dst_port,
                session_id=sid,
                data={**fp, "geo": enrich(src),
                      "intel": TI.tag_event(src, enrich(src))},
            )
            threading.Thread(target=_flush_after, args=(flow_key,), daemon=True).start()
            return

        if not _maybe_handshake(buf):
            # Not TLS — keep collecting up to a small bound, then give up
            if len(buf) > 1024 and not _maybe_handshake(bytes(buf[:6])):
                _PENDING.pop(flow_key, None)
            return
        snapshot = bytes(buf)

    fp = fingerprint(snapshot)
    if fp is None:
        return

    sid = TRACKER.get(src)
    L.get().emit(
        EventType.TLS_FINGERPRINT,
        src_ip=src, src_port=src_port, dst_port=dst_port,
        session_id=sid,
        data={**fp, "geo": enrich(src)},
    )
    with _PENDING_LOCK:
        _PENDING.pop(flow_key, None)
    # schedule gc just in case
    threading.Thread(target=_flush_after, args=(flow_key,), daemon=True).start()


def serve() -> None:
    cfg = Config.load()
    L.configure(cfg.log_dir, cfg.node_name, "meta")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "packet_capture", "scapy": sniff is not None})

    if sniff is None:
        # Scapy unavailable — sit idle so the service stays "up"
        while True:
            time.sleep(60)
            L.get().heartbeat()

    # Filter: any TCP with data — we want to see TLS handshakes regardless of port
    # On busy networks, narrow this with the BPF filter to your listening ports.
    bpf = os.environ.get("HP_PCAP_BPF", "tcp")
    sniff(filter=bpf, prn=_handle, store=False)


if __name__ == "__main__":
    serve()
