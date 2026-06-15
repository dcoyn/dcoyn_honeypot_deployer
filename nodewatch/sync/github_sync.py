"""
nodewatch.sync.github_sync
=========================

Glue between aggregator and the private logs repo.

Run via systemd timer every N minutes:

  1. aggregator.run() — produces / updates files inside repo_dir
  2. git add . && git commit (only if something changed) && git push
  3. maintain() — keep the local footprint under a disk budget

We do NOT push raw events.jsonl from /var/log; raw events live under
the repo's events/YYYY/MM/DD/*.jsonl tree that the aggregator writes.

Auth: uses the token stashed at $DATA/.token by install.sh, embedded
into the remote URL as ``x-access-token``.

Disk budget
-----------
The per-node repo and its git history are the main disk consumer on a
node. ``maintain()`` keeps ``$DATA`` + ``$LOG_DIR`` under
``HP_DISK_BUDGET_GB`` (default 8) in three tiers, cheapest first:

  1. ``git gc`` (daily) — packs + delta-compresses loose objects. On a
     repo that has never been gc'd this is the dominant win (the many
     near-identical rewritten JSON profiles delta-compress enormously).
  2. shallow truncation (weekly, or immediately when over budget) —
     ``git fetch --depth=1`` + reset to ``origin/main`` so the *local*
     clone forgets old history. The remote keeps full history, so this
     never rewrites the remote and the central aggregator is unaffected.
  3. raw-event trimming (only if still over budget) — delete the oldest
     ``events/YYYY/MM/DD`` directories from the working tree and push the
     deletion, always keeping at least ``HP_MIN_EVENT_DAYS`` (default 14).
     The remote's git history still retains them.

All of this runs as the sync user (the repo owner), so it never creates
root-owned objects and never breaks the next push. The aggregator cursor
lives at ``.git/hp-state.json`` and is untracked, so gc / shallow / reset
all leave it intact.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config
from . import aggregator


# Bound git's memory use — these boxes can have as little as 384 MB RAM, and
# an un-gc'd repo can hold tens of thousands of loose objects.
_GC_MEM_FLAGS = ["-c", "pack.threads=1",
                 "-c", "pack.windowMemory=64m",
                 "-c", "pack.deltaCacheSize=32m"]


def _sh(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _ensure_remote(cfg: Config, repo: Path) -> None:
    """Make sure remote 'origin' is set with our token-embedded URL."""
    if not cfg.repo_url or not cfg.token:
        return
    auth_url = cfg.repo_url.replace("https://", f"https://x-access-token:{cfg.token}@")
    rc, out, _ = _sh(["git", "remote", "get-url", "origin"], repo)
    if rc != 0:
        _sh(["git", "remote", "add", "origin", auth_url], repo)
    else:
        if out != auth_url:
            _sh(["git", "remote", "set-url", "origin", auth_url], repo)


# ----------------------------------------------------------------- maintenance
def _du_bytes(path: str) -> int:
    """Disk usage of a path in bytes (block usage, like df sees it)."""
    if not path or not os.path.exists(path):
        return 0
    rc, out, _ = _sh(["du", "-sk", path], Path("/"))
    try:
        return int(out.split()[0]) * 1024
    except Exception:
        return 0


def _load_marker(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_marker(p: Path, d: dict) -> None:
    try:
        p.write_text(json.dumps(d))
    except Exception:
        pass


def _event_days(repo: Path) -> list[tuple[str, str]]:
    """Return (YYYYMMDD, relpath) for every events/YYYY/MM/DD dir, oldest first."""
    base = repo / "events"
    out: list[tuple[str, str]] = []
    if not base.is_dir():
        return out
    for y in base.iterdir():
        if not (y.is_dir() and y.name.isdigit()):
            continue
        for m in y.iterdir():
            if not (m.is_dir() and m.name.isdigit()):
                continue
            for d in m.iterdir():
                if d.is_dir() and d.name.isdigit():
                    out.append((f"{y.name}{m.name.zfill(2)}{d.name.zfill(2)}",
                                f"events/{y.name}/{m.name}/{d.name}"))
    out.sort(key=lambda t: t[0])
    return out


def maintain(cfg: Config, repo: Path) -> None:
    """Keep $DATA + $LOG_DIR under HP_DISK_BUDGET_GB. Best-effort; never raises."""
    try:
        budget = int(float(os.environ.get("HP_DISK_BUDGET_GB", "8")) * (1024 ** 3))
    except Exception:
        budget = 8 * 1024 ** 3
    try:
        min_days = max(0, int(os.environ.get("HP_MIN_EVENT_DAYS", "14")))
    except Exception:
        min_days = 14

    marker = repo / ".git" / "hp-maint.json"
    g = _load_marker(marker)
    now = time.time()

    def footprint() -> int:
        return _du_bytes(cfg.data_dir) + _du_bytes(cfg.log_dir)

    used = footprint()
    over = used > budget
    gc_due = over or (now - g.get("last_gc", 0) > 86400)

    if gc_due:
        # Only re-anchor to the remote tip when the tree is clean (it is, right
        # after a successful push), so we never discard un-pushed work.
        _, status, _ = _sh(["git", "status", "--porcelain"], repo)
        clean = (status == "")
        shallow_due = over or (now - g.get("last_shallow", 0) > 7 * 86400)
        if shallow_due and clean:
            rc, _, err = _sh(["git", "fetch", "--depth=1", "origin", "main"], repo)
            if rc == 0:
                _sh(["git", "reset", "--hard", "origin/main"], repo)
                g["last_shallow"] = now
            else:
                print(f"[maint] shallow fetch skipped: {err}", file=sys.stderr)
        _sh(["git", "reflog", "expire", "--expire=now", "--all"], repo)
        rc, _, err = _sh(["git"] + _GC_MEM_FLAGS + ["gc", "--prune=now", "--quiet"], repo)
        if rc != 0:
            print(f"[maint] gc failed: {err}", file=sys.stderr)
        g["last_gc"] = now
        used = footprint()

    # Tier 3 — still over budget: trim oldest raw-event days from the tree.
    if used > budget:
        days = _event_days(repo)
        deletable = days[:-min_days] if min_days else days
        removed: list[str] = []
        for _date, rel in deletable:
            if used <= budget:
                break
            sz = _du_bytes(str(repo / rel))
            rc, _, _ = _sh(["git", "rm", "-r", "-q", "--", rel], repo)
            if rc != 0:
                shutil.rmtree(repo / rel, ignore_errors=True)
            removed.append(rel)
            used -= sz
        if removed:
            cap_mb = budget // 1024 // 1024
            _sh(["git", "add", "-A"], repo)
            _sh(["git", "commit", "-q", "-m",
                 f"maint: prune {len(removed)} old raw-event day(s) to stay under {cap_mb}MB"], repo)
            rc, _, err = _sh(["git", "push", "origin", "main"], repo)
            if rc != 0:
                print(f"[maint] push of pruned tree failed: {err}", file=sys.stderr)
            print(f"[maint] pruned {len(removed)} event-day dir(s) from the tree "
                  f"(remote git history retains them); footprint now ~{used // 1024 // 1024}MB")
        else:
            print(f"[maint] over budget ({used // 1024 // 1024}MB > "
                  f"{budget // 1024 // 1024}MB) but nothing past the "
                  f"{min_days}-day floor to trim", file=sys.stderr)

    _save_marker(marker, g)


def main() -> int:
    cfg  = Config.load()
    repo = Path(cfg.repo_dir)
    repo.mkdir(parents=True, exist_ok=True)

    if not (repo / ".git").exists():
        _sh(["git", "init", "-b", "main"], repo)

    _sh(["git", "config", "user.email", "agent@local"], repo)
    _sh(["git", "config", "user.name",  "agent-bot"],  repo)
    _ensure_remote(cfg, repo)

    summary = aggregator.run()
    if summary["events_processed"] == 0:
        # Still touch a heartbeat so we know the node is alive
        (repo / "nodes").mkdir(parents=True, exist_ok=True)

    _sh(["git", "add", "-A"], repo)
    _sh_rc, out, _ = _sh(["git", "status", "--porcelain"], repo)
    if not out:
        print(f"[sync] nothing to commit (events_processed={summary['events_processed']})")
        # Repo can still be over budget even with no new events.
        maintain(cfg, repo)
        return 0

    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    msg = f"{cfg.node_name}: +{summary['events_processed']} events @ {ts}"
    rc, out, err = _sh(["git", "commit", "-m", msg], repo)
    if rc != 0:
        print(f"[sync] commit failed: {err}", file=sys.stderr)

    # Try a pull --rebase first to play nicely with hundreds of nodes
    _sh(["git", "fetch", "origin"], repo)
    _sh(["git", "pull", "--rebase", "--autostash", "origin", "main"], repo)
    rc, out, err = _sh(["git", "push", "-u", "origin", "main"], repo)
    if rc != 0:
        print(f"[sync] push failed: {err}", file=sys.stderr)
        return 1

    print(f"[sync] pushed: {msg}")
    maintain(cfg, repo)
    return 0


if __name__ == "__main__":
    sys.exit(main())