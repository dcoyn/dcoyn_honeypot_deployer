"""
nodewatch.sync.github_sync
=========================

Glue between aggregator and the private logs repo.

Run via systemd timer every N minutes:

  1. aggregator.run() — produces / updates files inside repo_dir
  2. git add . && git commit (only if something changed) && git push

We do NOT push raw events.jsonl from /var/log; raw events live under
the repo's events/YYYY/MM/DD/*.jsonl tree that the aggregator writes.

Auth: uses the token stashed at $DATA/.token by install.sh, embedded
into the remote URL as ``x-access-token``.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config
from . import aggregator


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
    rc, out, _ = _sh(["git", "status", "--porcelain"], repo)
    if not out:
        print(f"[sync] nothing to commit (events_processed={summary['events_processed']})")
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
