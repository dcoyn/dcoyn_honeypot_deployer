"""
config
======

Reads the agent config.json (path overridable via HP_CONFIG env var)
and exposes typed accessors. Falls back to env vars so tests run
without install.

Path layout on a real install is determined by the installer; this
module only stores the values, not the layout.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# The installer writes config.json under /opt/<agent_name>/.
# HP_CONFIG overrides this for tests and ad-hoc runs.
DEFAULT_CONFIG_PATH = "/opt/nodewatch/config.json"


@dataclass
class Config:
    node_name: str
    sensor_profile: str          # ssh | owa | winserver
    log_dir: str
    data_dir: str
    repo_dir: str
    repo_url: str
    admin_ssh_port: int

    @classmethod
    def load(cls, path: str = DEFAULT_CONFIG_PATH) -> "Config":
        p = Path(os.environ.get("HP_CONFIG", path))
        if p.exists():
            raw = json.loads(p.read_text())
        else:
            raw = {}
        # Accept both new "sensor_profile" and legacy "honeypot_type" for compat
        profile = (raw.get("sensor_profile")
                   or raw.get("honeypot_type")
                   or os.environ.get("HP_TYPE", "ssh"))
        return cls(
            node_name      = raw.get("node_name")     or os.environ.get("HP_NODE_NAME", "dev-node"),
            sensor_profile = profile,
            log_dir        = raw.get("log_dir")       or os.environ.get("HP_LOG_DIR", "/var/log/nodewatch"),
            data_dir       = raw.get("data_dir")      or os.environ.get("HP_DATA_DIR", "/var/lib/nodewatch"),
            repo_dir       = raw.get("repo_dir")      or os.environ.get("HP_REPO_DIR", "/var/lib/nodewatch/repo"),
            repo_url       = raw.get("repo_url")      or os.environ.get("HP_REPO", ""),
            admin_ssh_port = int(raw.get("admin_ssh_port") or os.environ.get("HP_SSH_PORT", 62222)),
        )

    @property
    def token(self) -> str:
        """Git access token, kept in a root-only file by the installer."""
        p = Path(self.data_dir) / ".token"
        if p.exists():
            return p.read_text().strip()
        return os.environ.get("HP_GIT_TOKEN", "")
