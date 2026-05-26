"""
runner
======

Single entry point launched by systemd. Picks the configured sensor
profile and runs it. Keeps imports lazy so a crash in one sensor's
deps doesn't take down config loading.
"""
from __future__ import annotations

import sys

from .config import Config


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
        from .sensors import fileshare_sensor
        fileshare_sensor.serve()
    else:
        print(f"unknown sensor_profile: {t}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
