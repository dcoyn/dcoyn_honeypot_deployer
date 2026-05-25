"""
network.connection_logger
=========================

Tails the kernel-driven connection log (written by rsyslog from
nftables) and converts each line into a structured event.

The nftables ``log prefix`` is parameterised by the installer via the
``HP_NFT_PREFIX`` env var (default ``HPNEW_``). A line looks like:

  Jun 12 09:14:21 host01 kernel: HPNEW_TCP IN=eth0 OUT= MAC=...
   SRC=203.0.113.5 DST=10.0.0.7 LEN=60 ...
   PROTO=TCP SPT=51201 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0

This module parses it and writes a CONNECTION event so:
  * Every probe to every closed/silent port shows up in our data.
  * It's reconciled with application events by src_ip+session_id.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich

# Defaults are dev-friendly. The installer overrides via the env file
# (HP_CONNLOG_PATH, HP_NFT_PREFIX) so each fleet name has its own log path
# and its own nftables prefix tag.
DEFAULT_LOG_FILE = "/var/log/nodewatch/kernel-connections.log"
DEFAULT_NFT_PREFIX = "HPNEW_"

_KV = re.compile(r"(\w+)=([^\s]+)")


def _parse(line: str, prefix: str) -> dict | None:
    if prefix not in line:
        return None
    tcp_tag  = f"{prefix}TCP"
    udp_tag  = f"{prefix}UDP"
    icmp_tag = f"{prefix}ICMP"
    tag = tcp_tag if f"{tcp_tag} " in line else \
          udp_tag if f"{udp_tag} " in line else \
          icmp_tag
    kv = dict(_KV.findall(line))
    return {
        "tag": tag,
        "src": kv.get("SRC"),
        "dst": kv.get("DST"),
        "proto": kv.get("PROTO", "").lower() or tag.rsplit("_", 1)[-1].lower(),
        "spt": int(kv["SPT"]) if "SPT" in kv else 0,
        "dpt": int(kv["DPT"]) if "DPT" in kv else 0,
        "ttl": int(kv["TTL"]) if "TTL" in kv else None,
        "len": int(kv["LEN"]) if "LEN" in kv else None,
        "flags": [t for t in ["SYN","ACK","FIN","RST","PSH","URG"] if f" {t} " in line],
    }


def _tail(path: str):
    """Generator that yields new lines as they appear (with rotation handling)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.touch(exist_ok=True)
    fh = open(p, "r", encoding="utf-8", errors="replace")
    fh.seek(0, 2)  # end
    inode = p.stat().st_ino
    while True:
        line = fh.readline()
        if line:
            yield line
            continue
        time.sleep(0.5)
        try:
            cur = p.stat().st_ino
            if cur != inode:
                fh.close()
                fh = open(p, "r", encoding="utf-8", errors="replace")
                inode = cur
        except FileNotFoundError:
            time.sleep(1)


def serve() -> None:
    cfg = Config.load()
    log_path = os.environ.get("HP_CONNLOG_PATH", DEFAULT_LOG_FILE)
    prefix   = os.environ.get("HP_NFT_PREFIX", DEFAULT_NFT_PREFIX)
    L.configure(cfg.log_dir, cfg.node_name, "meta")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "connection_logger",
                       "source": log_path, "prefix": prefix})

    for line in _tail(log_path):
        parsed = _parse(line, prefix)
        if not parsed or not parsed.get("src"):
            continue
        sid = TRACKER.get(parsed["src"])
        L.get().emit(
            EventType.CONNECTION,
            src_ip=parsed["src"], src_port=parsed["spt"], dst_port=parsed["dpt"],
            proto=parsed["proto"],
            session_id=sid,
            data={
                "tag":   parsed["tag"],
                "ttl":   parsed["ttl"],
                "len":   parsed["len"],
                "flags": parsed["flags"],
                "geo":   enrich(parsed["src"]),
            },
        )


if __name__ == "__main__":
    serve()
