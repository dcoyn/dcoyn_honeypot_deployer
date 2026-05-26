"""
runner
======

Single entry point launched by systemd. Picks the configured sensor
profile and runs it. Keeps imports lazy so a crash in one sensor's
deps doesn't take down config loading.

`fileshare` is a special case: it ALSO runs the SSH sensor on port 22.
A real Linux box exposing files over HTTP would have SSH; binding 22
makes the honeypot more credible and captures attackers who probe SSH
after they find the share. Both sensors share the same FakeWorld so
the universe (org name, secrets, etc.) is consistent across ports.
"""
from __future__ import annotations

import sys
import threading
import time

from .config import Config


def _run_combined_fileshare() -> int:
    """fileshare profile = file share on 80/443 + SSH sensor on 22.
    Both sensors run in their own threads. If either dies, return non-zero
    so systemd restarts the whole service."""
    from .sensors import fileshare_sensor, ssh_sensor

    threads: dict[str, threading.Thread] = {
        "ssh":       threading.Thread(target=ssh_sensor.serve,       daemon=True, name="ssh-sensor"),
        "fileshare": threading.Thread(target=fileshare_sensor.serve, daemon=True, name="fileshare-sensor"),
    }
    for th in threads.values():
        th.start()

    # Watchdog: if any sensor thread exits, abort so systemd restarts everything
    while True:
        time.sleep(5)
        for name, th in threads.items():
            if not th.is_alive():
                print(f"sensor thread {name!r} exited; aborting for systemd restart",
                      file=sys.stderr)
                return 1


def main() -> int:
    cfg = Config.load()
    t = cfg.sensor_profile
    if t == "ssh":
        from .sensors import ssh_sensor
        ssh_sensor.serve()
    elif t == "owa":
        from .sensors import owa_sensor
        owa_sensor.serve()
    elif t == "winserver":
        from .sensors import win_sensor
        win_sensor.serve()
    elif t == "fileshare":
        return _run_combined_fileshare()
    else:
        print(f"unknown sensor_profile: {t}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
