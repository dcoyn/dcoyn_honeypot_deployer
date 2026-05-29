"""
sync.aggregator
===============

Reads events.jsonl and writes this node's view into the per-node repo.

Per-node repo layout (one repo per VM):

  events/YYYY/MM/DD/<node>-HH.jsonl   raw events (append-only)
  ips/<ip>.json                        this node's view of that IP
  sessions/<sid>.json                  sessions this node observed
  node.json                            this node's heartbeat + counters

Cross-node aggregation (consolidated `ips/` across the whole fleet, ASN
indexes, credential corpus, JA4 indexes, command corpora) is performed by
a SEPARATE central aggregator — see tools/central_aggregator.py in the
deployer repo. That tool clones every per-node repo and folds them into a
single intel repo.

Idempotent: tracks the last-processed byte of events.jsonl in
$DATA/aggregator_state.json.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from ..config import Config


STATE_FILE = ".git/hp-state.json"   # inside repo dir; git ignores .git/*
RAW_EVENTS = "events.jsonl"


# ---------------------------------------------------------------- helpers
def _iter_events(events_path: Path, since_pos: int) -> Iterable[tuple[int, dict]]:
    """Yield (byte_offset_after_line, event) starting from ``since_pos``."""
    if not events_path.exists():
        return
    with open(events_path, "rb") as f:
        f.seek(since_pos)
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            yield f.tell(), obj


def _atomic_write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    os.replace(tmp, path)


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


# ---------------------------------------------------------------- main
def run() -> dict:
    cfg = Config.load()
    log_dir = Path(cfg.log_dir)
    repo    = Path(cfg.repo_dir)

    events_path = log_dir / RAW_EVENTS
    state_path  = Path(cfg.repo_dir) / STATE_FILE
    state       = _load_json(state_path, {"pos": 0})
    start_pos   = state.get("pos", 0)

    # Per-batch buffers
    ip_updates:    dict[str, dict] = defaultdict(dict)
    sess_updates:  dict[str, dict] = defaultdict(dict)
    raw_hour_buckets: dict[str, list] = defaultdict(list)

    new_pos = start_pos
    n_events = 0
    for new_pos, ev in _iter_events(events_path, start_pos):
        n_events += 1
        ip   = ev.get("src_ip") or "0.0.0.0"
        sid  = ev.get("session_id") or ""
        et   = ev.get("event_type")
        ts   = ev.get("ts")
        data = ev.get("data") or {}
        geo  = data.get("geo") or {}

        # ---- raw events by hour ---
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
        bucket = f"events/{dt:%Y/%m/%d}/{cfg.node_name}-{dt:%H}.jsonl"
        raw_hour_buckets[bucket].append(ev)

        # ---- IP profile (this node's view) ---
        ipd = ip_updates[ip]
        ipd.setdefault("ip", ip)
        ipd.setdefault("first_seen", ts)
        ipd["last_seen"] = ts
        ipd["event_count"] = ipd.get("event_count", 0) + 1
        ipd.setdefault("event_types", {})
        ipd["event_types"][et] = ipd["event_types"].get(et, 0) + 1
        ipd.setdefault("ports_hit", set())
        if ev.get("dst_port"):
            ipd["ports_hit"].add(int(ev["dst_port"]))
        ipd.setdefault("sensors", set())
        if ev.get("sensor_profile"):
            ipd["sensors"].add(ev["sensor_profile"])
        ipd.setdefault("sessions", set())
        if sid:
            ipd["sessions"].add(sid)
        if geo:
            ipd["geo"] = geo

        ua = data.get("user_agent")
        if ua:
            ipd.setdefault("user_agents", set()).add(ua[:300])

        if et == "tls_fingerprint":
            ja4 = data.get("ja4")
            if ja4:
                ipd.setdefault("ja4", set()).add(ja4)
            if data.get("ja3_hash"):
                ipd.setdefault("ja3", set()).add(data["ja3_hash"])

        if et in ("ssh_auth", "ssh_login_ok", "http_login"):
            ipd["cred_attempts"] = ipd.get("cred_attempts", 0) + 1
            if data.get("accepted") or et == "ssh_login_ok":
                ipd["cred_successes"] = ipd.get("cred_successes", 0) + 1

        if et == "ssh_command":
            ipd["commands_run"] = ipd.get("commands_run", 0) + 1

        # ---- attacker intelligence rollups ----
        intel = data.get("intel") or {}
        src_intel = intel.get("source") or {}
        if src_intel.get("infra"):
            ipd["infra"] = src_intel["infra"]
        if src_intel.get("provider"):
            ipd["provider"] = src_intel["provider"]
        if intel.get("automated") is True:
            ipd["automated"] = True
        sc = intel.get("ssh_client") or {}
        if sc.get("tool") and sc["tool"] != "unknown":
            ipd.setdefault("ssh_tools", set()).add(sc["tool"])
        hc = intel.get("http_client") or {}
        if hc.get("ua_class") and hc["ua_class"] not in ("unknown", "empty"):
            ipd.setdefault("http_tools", set()).add(hc["ua_class"])

        # HASSH from passive sniffer
        if et == "ssh_fingerprint" and data.get("hassh"):
            ipd.setdefault("hassh", set()).add(data["hassh"])

        # MITRE ATT&CK techniques + attack categories, from command / http classification
        cl = data.get("classification") or {}
        for tech in cl.get("techniques", []):
            ipd.setdefault("attack_techniques", set()).add(tech)
        cat = cl.get("category")
        if cat and cat not in ("navigation", "empty", "other"):
            ac = ipd.setdefault("attack_categories", {})
            ac[cat] = ac.get(cat, 0) + 1
        for ioc_ip in (cl.get("iocs") or {}).get("ips", []):
            ipd.setdefault("ioc_ips", set()).add(ioc_ip)
        for ioc_url in (cl.get("iocs") or {}).get("urls", []):
            ipd.setdefault("ioc_urls", set()).add(ioc_url)
        # Redis attack chains + telnet botnet probes
        if et == "redis_command" and data.get("attack_chain"):
            ipd.setdefault("redis_attack_chains", set()).add(data["attack_chain"])
        if et == "telnet_command" and data.get("botnet_probe"):
            ipd["botnet_probe"] = True
        for tech in data.get("techniques", []):  # redis emits techniques directly
            ipd.setdefault("attack_techniques", set()).add(tech)

        # ---- Docker API attack intelligence ----
        if et in ("docker_api", "docker_container_create"):
            for chain in data.get("attack_chains", []):
                ipd.setdefault("docker_attack_chains", set()).add(chain)
            for u in data.get("ioc_urls", []):
                ipd.setdefault("ioc_urls", set()).add(u)
            for ip4 in data.get("ioc_ips", []):
                ipd.setdefault("ioc_ips", set()).add(ip4)
            if data.get("image"):
                ipd.setdefault("docker_images", set()).add(data["image"][:200])
            for w in data.get("monero_wallets", []):
                ipd.setdefault("crypto_wallets", set()).add(w)
            for p in data.get("mining_pools", []):
                ipd.setdefault("mining_pools", set()).add(p)
            if et == "docker_container_create":
                ipd["deployed_container"] = True
            if any(c in ("host_filesystem_mount_escape", "privileged_container_escape",
                         "host_namespace_escape", "nsenter_host_escape")
                   for c in data.get("attack_chains", [])):
                ipd["docker_host_escape_attempt"] = True

        # ---- canary beacon intelligence ----
        ce = data.get("canary_event")
        if ce == "canary_beacon_received":
            ipd["opened_canary"] = True
            if data.get("canary_slot"):
                ipd.setdefault("canary_slots_fired", set()).add(data["canary_slot"])
            if data.get("opener_kind"):
                ipd["opener_kind"] = data["opener_kind"]
            # If this opener is a different IP than the downloader, record the
            # link so the scorecard shows the exfil→detonation relationship.
            if data.get("opener_is_different_ip") and data.get("downloader_ip"):
                ipd.setdefault("downloaded_from_ips", set()).add(data["downloader_ip"])
        elif ce == "canary_ntlm_credentials_captured":
            ipd["captured_credentials"] = True
            cred = {k: data.get(k) for k in ("domain", "username", "workstation")
                    if data.get(k)}
            if cred:
                # store as a compact "DOMAIN\\user@host" string set
                tag = f"{cred.get('domain','')}\\{cred.get('username','')}@{cred.get('workstation','')}"
                ipd.setdefault("captured_identities", set()).add(tag)
            if data.get("netntlmv2"):
                ipd.setdefault("captured_netntlmv2", set()).add(data["netntlmv2"][:600])

        # ---- session summary ---
        if sid:
            sd = sess_updates[sid]
            sd.setdefault("session_id", sid)
            sd.setdefault("ip", ip)
            sd.setdefault("first_seen", ts)
            sd["last_seen"] = ts
            sd["events"] = sd.get("events", 0) + 1
            sd.setdefault("event_types", {})
            sd["event_types"][et] = sd["event_types"].get(et, 0) + 1
            sd.setdefault("sensor", ev.get("sensor_profile"))
            if et == "ssh_command" and data.get("command"):
                sd.setdefault("commands", []).append(data["command"])
            if et == "ssh_login_ok":
                sd["login_ok"] = True
                sd["login_user"] = data.get("username")
            if et == "tls_fingerprint" and data.get("ja4"):
                sd.setdefault("ja4", data["ja4"])
            if et == "http_request" and data.get("user_agent"):
                sd.setdefault("user_agent", data["user_agent"])

    # ----------------------------------------------------------------- merge
    # Raw events to per-hour files
    for bucket, events in raw_hour_buckets.items():
        out = repo / bucket
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "a", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")

    # IP profiles (this-node view)
    for ip, upd in ip_updates.items():
        path = repo / "ips" / f"{ip}.json"
        existing = _load_json(path, {})
        for k in ("ports_hit", "sensors", "sessions", "user_agents", "ja3", "ja4",
                  "ssh_tools", "http_tools", "hassh", "attack_techniques",
                  "ioc_ips", "ioc_urls", "redis_attack_chains",
                  "canary_slots_fired", "downloaded_from_ips",
                  "captured_identities", "captured_netntlmv2",
                  "docker_attack_chains", "docker_images", "crypto_wallets",
                  "mining_pools"):
            if k in upd and isinstance(upd[k], set):
                upd[k] = sorted(upd[k])
            if k in existing and isinstance(existing[k], list):
                merged = set(existing[k]) | set(upd.get(k, []))
                upd[k] = sorted(merged)
        for k in ("event_count", "cred_attempts", "cred_successes", "commands_run"):
            if k in upd:
                upd[k] = existing.get(k, 0) + upd.get(k, 0)
        # attack_categories: per-category counters
        if "attack_categories" in upd or "attack_categories" in existing:
            merged = dict(existing.get("attack_categories", {}))
            for k, v in upd.get("attack_categories", {}).items():
                merged[k] = merged.get(k, 0) + v
            upd["attack_categories"] = merged
        # sticky boolean flags
        for k in ("automated", "botnet_probe", "opened_canary", "captured_credentials",
                  "deployed_container", "docker_host_escape_attempt"):
            if existing.get(k) or upd.get(k):
                upd[k] = True
        for k in ("infra", "provider", "opener_kind"):
            if k not in upd and k in existing:
                upd[k] = existing[k]
        if "event_types" in upd:
            merged = dict(existing.get("event_types", {}))
            for k, v in upd["event_types"].items():
                merged[k] = merged.get(k, 0) + v
            upd["event_types"] = merged
        if existing.get("first_seen") and existing["first_seen"] < upd.get("first_seen", "9"):
            upd["first_seen"] = existing["first_seen"]
        if "geo" not in upd and "geo" in existing:
            upd["geo"] = existing["geo"]
        _atomic_write_json(path, upd)

    # Session summaries
    for sid, upd in sess_updates.items():
        path = repo / "sessions" / f"{sid}.json"
        existing = _load_json(path, {})
        if "events" in upd:
            upd["events"] = existing.get("events", 0) + upd["events"]
        if "event_types" in upd:
            merged = dict(existing.get("event_types", {}))
            for k, v in upd["event_types"].items():
                merged[k] = merged.get(k, 0) + v
            upd["event_types"] = merged
        if existing.get("first_seen") and existing["first_seen"] < upd.get("first_seen", "9"):
            upd["first_seen"] = existing["first_seen"]
        if "commands" in upd:
            upd["commands"] = (existing.get("commands", []) + upd["commands"])[-5000:]
        _atomic_write_json(path, upd)

    # Node heartbeat (single file — this repo is one node)
    node_path = repo / "node.json"
    nd = _load_json(node_path, {})
    nd.update({
        "node_name":      cfg.node_name,
        "sensor_profile": cfg.sensor_profile,
        "last_aggregated_at": datetime.now(timezone.utc).isoformat(),
    })
    nd["total_events"] = nd.get("total_events", 0) + n_events
    _atomic_write_json(node_path, nd)

    # Persist read position
    _atomic_write_json(state_path, {
        "pos": new_pos,
        "last_run": nd["last_aggregated_at"],
        "last_count": n_events,
    })

    return {"events_processed": n_events, "new_pos": new_pos}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
