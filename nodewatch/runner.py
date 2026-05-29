"""
runner
======

Single entry point launched by systemd. Picks the configured sensor
profile and runs it. Keeps imports lazy so a crash in one sensor's
deps doesn't take down config loading.

Every profile also runs a canary **beacon receiver** so that a bait
document opened on an attacker's machine beacons straight back to this
same honeypot (HP_CANARY_URL is auto-pointed here at install):

  * fileshare / owa already serve HTTP on 80/443, so the beacon route is
    handled inside their own app.
  * ssh / telnet / redis / winserver don't speak HTTP, so a tiny
    standalone beacon listener is started on 80/443 alongside the sensor.

`fileshare` is additionally a special case: it ALSO runs the SSH sensor on
port 22, so a file-share box looks like a real Linux host.
"""
from __future__ import annotations

import sys
import threading
import time

from .config import Config


def _watchdog(threads: dict[str, threading.Thread]) -> int:
    """Block until any named thread dies, then return non-zero so systemd
    restarts the whole service. Threads must already be started."""
    while True:
        time.sleep(5)
        for name, th in threads.items():
            if not th.is_alive():
                print(f"thread {name!r} exited; aborting for systemd restart",
                      file=sys.stderr)
                return 1


def _run_combined_fileshare() -> int:
    """fileshare profile = file share on 80/443 + SSH sensor on 22.
    The beacon route lives inside the fileshare app already, so no separate
    receiver is needed here."""
    from .sensors import fileshare_sensor, ssh_sensor

    threads = {
        "ssh":       threading.Thread(target=ssh_sensor.serve,       daemon=True, name="ssh-sensor"),
        "fileshare": threading.Thread(target=fileshare_sensor.serve, daemon=True, name="fileshare-sensor"),
    }
    for th in threads.values():
        th.start()
    return _watchdog(threads)


def _run_with_beacon(sensor_serve) -> int:
    """Run a non-HTTP sensor in one thread and the standalone beacon receiver
    (80/443) in another, so canary opens are captured on this host too."""
    from .sensors import beacon

    threads = {
        "sensor": threading.Thread(target=sensor_serve,  daemon=True, name="sensor"),
        "beacon": threading.Thread(target=beacon.serve,  daemon=True, name="beacon-receiver"),
    }
    for th in threads.values():
        th.start()
    return _watchdog(threads)


def main() -> int:
    cfg = Config.load()
    t = cfg.sensor_profile
    if t == "ssh":
        from .sensors import ssh_sensor
        return _run_with_beacon(ssh_sensor.serve)
    elif t == "owa":
        # owa already serves 80/443 — install the beacon intercept on its app.
        from .sensors import owa_sensor, beacon
        beacon.install_beacon_intercept(owa_sensor.app)
        owa_sensor.serve()
    elif t == "winserver":
        from .sensors import win_sensor
        return _run_with_beacon(win_sensor.serve)
    elif t == "telnet":
        from .sensors import telnet_sensor
        return _run_with_beacon(telnet_sensor.serve)
    elif t == "redis":
        from .sensors import redis_sensor
        return _run_with_beacon(redis_sensor.serve)
    elif t == "docker":
        from .sensors import docker_sensor
        return _run_with_beacon(docker_sensor.serve)
    elif t == "fileshare":
        return _run_combined_fileshare()
    else:
        print(f"unknown sensor_profile: {t}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
