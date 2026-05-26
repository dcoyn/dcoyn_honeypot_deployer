"""
sensors.fileshare_sensor
=========================

Fake "misconfigured open file share" honeypot. Looks like an Apache box
with mod_autoindex left on — the kind of thing internet-wide scanners
find every day on Shodan/Censys and start downloading. Listens on
80 (HTTP) and 443 (HTTPS, self-signed).

What it exposes:
  * Directory listings in classic Apache mod_autoindex HTML.
  * Plausibly-named bait files (DB backups, CSV exports, .env, .git/,
    SSH keys tarball, internal docs).
  * Several DOCX/XLSX/HTML files that contain external image canaries.
    When the attacker exfiltrates and opens one, it beacons home with
    their real IP, User-Agent, and viewer fingerprint.
  * robots.txt with "Disallow" entries pointing at the most enticing
    directories — classic bait, scanners read robots.txt first.
  * Fake admin login at /admin/, fake API endpoints, fake /.git/.

What it logs:
  * Every HTTP method/path/headers/body/cookies/UA.
  * A `canary_file_downloaded` event when one of the beaconing files
    is fetched — links the download_id back to the source IP, so when
    the beacon hits the operator's receiver we know exactly which
    download triggered it.
  * Failed admin login attempts with submitted creds.

All identifying content (org name, person names, customer roster, bait
filenames, secrets) comes from the per-VM FakeWorld. Two installs from
the same public deployer never look alike.
"""
from __future__ import annotations

import base64
import html
import os
import re
import ssl
import time
import uuid
import zipfile
import io
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Callable

from flask import Flask, request, make_response, abort, Response

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich
from .fake_world import FakeWorld
from .fake_fs import FakeFS, DEFAULT_CANARY_BASE


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1MB max body — generous for POSTs


# --------------------------------------------------------------- module state
_SHARE: Optional["FileShare"] = None


def _get_share() -> "FileShare":
    global _SHARE
    if _SHARE is None:
        cfg = Config.load()
        agent = cfg.node_name or "kworker"
        world_path = Path(cfg.data_dir) / "fake_world.json"
        world = FakeWorld.load_or_create(agent, world_path)
        _SHARE = FileShare(world)
    return _SHARE


# --------------------------------------------------------------- request log
def _client_ip() -> str:
    return (request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
            .split(",")[0].strip())


def _log_request(event_type: str, extra: Optional[dict] = None) -> None:
    src_ip = _client_ip()
    sid = TRACKER.get(src_ip)
    headers = {k: (v[:2048] if isinstance(v, str) else v)
               for k, v in request.headers.items()}
    body_len = 0
    body_b64 = ""
    try:
        raw = request.get_data(cache=True) or b""
        body_len = len(raw)
        body_b64 = base64.b64encode(raw[:8192]).decode()
    except Exception:
        pass
    data = {
        "method":      request.method,
        "path":        request.path,
        "query":       request.query_string.decode("latin-1"),
        "host":        request.host,
        "scheme":      request.scheme,
        "user_agent":  request.headers.get("User-Agent", ""),
        "referer":     request.headers.get("Referer", ""),
        "accept_lang": request.headers.get("Accept-Language", ""),
        "headers":     headers,
        "cookies":     {k: v[:512] for k, v in request.cookies.items()},
        "body_len":    body_len,
        "body_b64":    body_b64,
        "geo":         enrich(src_ip),
    }
    if extra:
        data.update(extra)
    L.get().emit(
        event_type,
        src_ip=src_ip, src_port=0,
        dst_port=request.environ.get("SERVER_PORT", 443),
        session_id=sid,
        data=data,
        sensor_profile="fileshare",
    )


@app.before_request
def _trace():
    request.environ["_HP_T0"] = time.monotonic()
    _log_request(EventType.HTTP_REQUEST)


@app.after_request
def _hdrs(resp):
    t0 = request.environ.get("_HP_T0")
    if t0:
        resp.headers["X-Response-Time-Ms"] = str(int((time.monotonic() - t0) * 1000))
    # Look like a stock Apache on Ubuntu — what an exposed share would be
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    return resp


# ============================================================ file share
class FileShare:
    """Per-VM tree of fake files exposed via Apache-style autoindex."""

    def __init__(self, world: FakeWorld) -> None:
        self.world = world
        self.agent = world.agent_name
        self.v = dict(world.values)
        self.canary_base = os.environ.get("HP_CANARY_URL", DEFAULT_CANARY_BASE).rstrip("/")

        # Derived values consumed by some template strings
        now = datetime.now(timezone.utc)
        self.v["today"]         = now.strftime("%Y-%m-%d")
        self.v["last_rotated"]  = (now - timedelta(days=42)).strftime("%Y-%m-%d")
        self.v["host"]          = world.values.get("org_short", "host")

        # We piggyback FakeFS's canary doc builders — same DOCX/XLSX format.
        self._fs = FakeFS(world=world, hostname=world.values.get("org_short", "host"),
                          canary_base=self.canary_base)

        # Stable RNG per VM for filenames/timestamps that don't carry
        # FakeWorld-level randomization
        import hashlib, random as _r
        seed = hashlib.sha256(f"{self.agent}|share".encode()).digest()
        self._rng = _r.Random(int.from_bytes(seed[:8], "big"))

        self.files: dict[str, tuple[bytes, datetime, str]] = {}  # path -> (bytes, mtime, mime)
        self.canaries: dict[str, tuple[str, Callable[[str], bytes]]] = {}  # path -> (mime, builder)
        self.dirs: set[str] = {"/"}

        self._build()

    # ---------------------------------------------------- public api
    def has_file(self, path: str) -> bool:
        p = self._norm(path)
        return p in self.files or p in self.canaries

    def has_dir(self, path: str) -> bool:
        return self._norm(path) in self.dirs

    def is_canary(self, path: str) -> bool:
        return self._norm(path) in self.canaries

    def read(self, path: str, *, download_id: str) -> tuple[bytes, str, datetime]:
        """Returns (bytes, content_type, mtime) for a file path."""
        p = self._norm(path)
        if p in self.canaries:
            mime, builder = self.canaries[p]
            return builder(download_id), mime, self._canary_mtimes[p]
        if p in self.files:
            data, mtime, mime = self.files[p]
            return data, mime, mtime
        raise FileNotFoundError(p)

    def list_dir(self, path: str) -> list[tuple[str, datetime, int, bool]]:
        """List a directory: (name, mtime, size, is_dir)."""
        p = self._norm(path)
        if p not in self.dirs:
            raise NotADirectoryError(p)
        prefix = p.rstrip("/") + "/" if p != "/" else "/"

        children: dict[str, tuple[datetime, int, bool]] = {}
        # files
        for fp, (data, mtime, _mime) in self.files.items():
            if not fp.startswith(prefix):
                continue
            rest = fp[len(prefix):]
            if not rest:
                continue
            name = rest.split("/", 1)[0]
            if "/" in rest:
                # it's inside a subdir → represent that subdir
                children.setdefault(name, (mtime, 4096, True))
            else:
                children[name] = (mtime, len(data), False)
        # canaries
        for cp in self.canaries:
            if not cp.startswith(prefix):
                continue
            rest = cp[len(prefix):]
            if not rest or "/" in rest:
                continue
            mtime = self._canary_mtimes[cp]
            children[rest] = (mtime, self._canary_sizes[cp], False)
        # nested dirs that aren't covered above
        for d in self.dirs:
            if not d.startswith(prefix) or d == p:
                continue
            rest = d[len(prefix):]
            name = rest.split("/", 1)[0]
            children.setdefault(name, (self._dir_mtime, 4096, True))

        out = [(name, *meta) for name, meta in children.items()]
        out.sort(key=lambda r: (not r[3], r[0].lower()))  # dirs first
        return out

    @staticmethod
    def _norm(path: str) -> str:
        if not path:
            return "/"
        # Strip query, collapse double slashes
        path = re.sub(r"//+", "/", path.split("?", 1)[0])
        if not path.startswith("/"):
            path = "/" + path
        # Resolve simple .. without escaping root
        parts: list[str] = []
        for seg in path.split("/"):
            if seg == "..":
                if parts:
                    parts.pop()
            elif seg and seg != ".":
                parts.append(seg)
        return "/" + "/".join(parts)

    # ---------------------------------------------------- build
    def _build(self) -> None:
        v = self.v
        rng = self._rng

        # Common mime guesses
        MIME = {
            ".html": "text/html; charset=utf-8",
            ".htm":  "text/html; charset=utf-8",
            ".txt":  "text/plain; charset=utf-8",
            ".md":   "text/markdown; charset=utf-8",
            ".csv":  "text/csv; charset=utf-8",
            ".json": "application/json",
            ".yaml": "application/yaml",
            ".yml":  "application/yaml",
            ".sql":  "application/sql",
            ".gz":   "application/gzip",
            ".tar":  "application/x-tar",
            ".tgz":  "application/gzip",
            ".log":  "text/plain; charset=utf-8",
            ".key":  "application/x-pem-file",
            ".crt":  "application/x-x509-ca-cert",
            ".pem":  "application/x-pem-file",
            ".pdf":  "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".env":  "text/plain; charset=utf-8",
            "":      "application/octet-stream",
        }

        def _mime_for(path: str) -> str:
            base = path.rsplit("/", 1)[-1]
            if "." not in base:
                return MIME[""]
            ext = "." + base.rsplit(".", 1)[-1].lower()
            return MIME.get(ext, MIME[""])

        def add(path: str, content, *, mtime_offset_h: int = 0):
            if isinstance(content, str):
                try:
                    content = content.format(**v).encode("utf-8")
                except (KeyError, IndexError):
                    content = content.encode("utf-8")
            mtime = datetime.now(timezone.utc) - timedelta(hours=mtime_offset_h)
            self.files[path] = (content, mtime, _mime_for(path))

        def add_bytes(path: str, content: bytes, *, mtime_offset_h: int = 0):
            mtime = datetime.now(timezone.utc) - timedelta(hours=mtime_offset_h)
            self.files[path] = (content, mtime, _mime_for(path))

        # Default mtime for directories
        self._dir_mtime = datetime.now(timezone.utc) - timedelta(days=14)

        # ----- root -----
        add("/index.html", _ROOT_INDEX_HTML, mtime_offset_h=720)  # 30 days old
        add("/README.txt", _README_TXT, mtime_offset_h=480)
        add("/robots.txt", _ROBOTS_TXT, mtime_offset_h=1200)
        add("/.env", _ENV_FILE, mtime_offset_h=24)
        add("/.htaccess", _HTACCESS, mtime_offset_h=2000)

        # ----- /.git/ — classic "exposed git" -----
        add("/.git/HEAD", "ref: refs/heads/main\n", mtime_offset_h=720)
        add("/.git/config", _GIT_CONFIG, mtime_offset_h=720)
        add("/.git/description", "Unnamed repository; edit this file 'description' to name the repository.\n",
            mtime_offset_h=2000)
        add("/.git/refs/heads/main",
            "".join(rng.choice("0123456789abcdef") for _ in range(40)) + "\n",
            mtime_offset_h=72)
        add("/.git/packed-refs",
            "# pack-refs with: peeled fully-peeled sorted\n"
            "" + "".join(rng.choice("0123456789abcdef") for _ in range(40)) +
            " refs/heads/main\n",
            mtime_offset_h=720)
        # A fake packed object that just LOOKS like a real one
        add_bytes("/.git/objects/pack/pack-" + "".join(rng.choice("0123456789abcdef") for _ in range(40)) + ".idx",
                  b"\xfftOc\x00\x00\x00\x02" + bytes(rng.randint(0, 255) for _ in range(2048)),
                  mtime_offset_h=720)

        # ----- /backups/ -----
        for days_ago in (3, 17, 34, 65, 96):
            tstamp = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")
            gz_header = b"\x1f\x8b\x08\x00" + bytes(rng.randint(0, 255) for _ in range(4))
            body = gz_header + bytes(rng.randint(0, 255) for _ in range(rng.randint(40000, 120000)))
            add_bytes(f"/backups/db_backup_{tstamp}.sql.gz", body,
                      mtime_offset_h=days_ago * 24)
        # Plain-text SQL preview (gold mine for attackers)
        add("/backups/last_dump_preview.sql", _SQL_PREVIEW, mtime_offset_h=72)
        add("/backups/customers_export.csv", self._build_customers_csv(), mtime_offset_h=72)
        add("/backups/financial_summary_2025.csv", self._build_financials_csv(),
            mtime_offset_h=240)
        add("/backups/README.txt",
            f"Nightly database dumps from db-prod-01.{v['int_domain']}.\n"
            f"Retention: 90 days. SSE-S3 mirror in s3://{v['org_short']}-prod-backups/.\n",
            mtime_offset_h=2000)

        # ----- /docs/ -----
        add("/docs/runbook.md", _RUNBOOK_MD, mtime_offset_h=336)
        add("/docs/architecture.md", _ARCH_MD, mtime_offset_h=672)
        add("/docs/onboarding.md", _ONBOARDING_MD, mtime_offset_h=120)

        # ----- /exports/ -----
        add("/exports/users_export.csv", self._build_users_csv(), mtime_offset_h=72)
        add("/exports/api_call_log_2025-Q4.csv", self._build_api_log_csv(),
            mtime_offset_h=72)

        # ----- /private/ — the "shouldn't be public" feel -----
        add("/private/credentials.txt", _CREDENTIALS_TXT, mtime_offset_h=72)
        add("/private/.htpasswd",
            f"admin:$apr1${''.join(rng.choice('./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(8))}$"
            f"{''.join(rng.choice('./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(22))}\n"
            f"{v['ops_first'].lower()}:$apr1${''.join(rng.choice('./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(8))}$"
            f"{''.join(rng.choice('./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(22))}\n",
            mtime_offset_h=240)
        add("/private/ssl/private.key", _PRIVATE_KEY, mtime_offset_h=720)
        add("/private/ssl/certificate.crt", _CERTIFICATE, mtime_offset_h=720)
        # Fake SSH keys tarball (binary)
        ssh_keys_blob = bytes(rng.randint(0, 255) for _ in range(8192))
        add_bytes("/private/ssh_keys_backup.tar.gz",
                  b"\x1f\x8b\x08\x00" + bytes(rng.randint(0, 255) for _ in range(4)) + ssh_keys_blob,
                  mtime_offset_h=720)
        add("/private/aws_keys_rotation.txt", _AWS_ROTATION_TXT, mtime_offset_h=72)

        # ----- /uploads/ — invoices etc -----
        for inv in range(rng.randint(4, 8)):
            num = rng.randint(1000, 9999)
            add_bytes(f"/uploads/invoices/INV-{num}.pdf",
                      b"%PDF-1.4\n%" + bytes(rng.randint(0, 255) for _ in range(8))
                      + b"\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\nxref\n"
                      + bytes(rng.randint(0, 255) for _ in range(2048)),
                      mtime_offset_h=rng.randint(48, 720))

        # ----- /api/ — fake JSON endpoints (still log probes) -----
        add("/api/v1/health.json", '{"status": "ok"}\n', mtime_offset_h=720)
        add("/api/openapi.json", _OPENAPI_JSON, mtime_offset_h=720)

        # ----- canaries: docx + xlsx + html, randomized filenames per VM -----
        # Pull bait filenames from FakeWorld so each install differs.
        cdoc = v["canary_doc_name"]              # e.g. "vault-export"
        cxls = v["canary_xls_name"]              # e.g. "customers-Q1"
        cdoc_bk = v["canary_doc_backup_name"]   # different from cdoc

        self._canary_mtimes: dict[str, datetime] = {}
        self._canary_sizes:  dict[str, int]      = {}

        def add_canary(path: str, mime: str, builder: Callable[[str], bytes],
                       *, mtime_offset_h: int, size_hint: int):
            self.canaries[path] = (mime, builder)
            self._canary_mtimes[path] = datetime.now(timezone.utc) - timedelta(hours=mtime_offset_h)
            self._canary_sizes[path] = size_hint

        # The actual docx/xlsx builders live on FakeFS — reuse them
        add_canary(f"/docs/{cdoc}.docx", MIME[".docx"],
                   self._fs._build_canary_docx,
                   mtime_offset_h=120, size_hint=21000)
        add_canary(f"/exports/{cxls}.xlsx", MIME[".xlsx"],
                   self._fs._build_canary_xlsx,
                   mtime_offset_h=72, size_hint=18000)
        add_canary(f"/private/{cdoc_bk}.docx", MIME[".docx"],
                   self._fs._build_canary_docx,
                   mtime_offset_h=240, size_hint=22000)
        # HTML canary — opens in any browser → instant beacon
        add_canary("/docs/internal-status-report.html", MIME[".html"],
                   self._build_html_canary,
                   mtime_offset_h=48, size_hint=8400)

        # ----- compute the set of all directories (implicit from file paths) -----
        for path in list(self.files.keys()) + list(self.canaries.keys()):
            parts = path.strip("/").split("/")
            for i in range(1, len(parts)):
                d = "/" + "/".join(parts[:i])
                self.dirs.add(d)

    # ---------- per-VM CSV/SQL content from FakeWorld customer roster ----------
    def _build_customers_csv(self) -> bytes:
        rows = ["customer_id,email,name,company,plan,monthly_value_usd,signup_date,country"]
        for c in self.v.get("customers", []):
            rows.append(f'{c["id"]},{c["email"]},{c["name"]},'
                         f'"{c["company"]}",{c["plan"]},{c["mrr_usd"]},'
                         f'{c["signup_date"]},{c["country"]}')
        return ("\n".join(rows) + "\n").encode()

    def _build_users_csv(self) -> bytes:
        rng = self._rng
        rows = ["user_id,email,role,last_login,mfa_enabled"]
        for i in range(1, 24):
            c = self.v["customers"][i % len(self.v["customers"])]
            rows.append(f"{1000+i},{c['email'].replace('@', f'.{i}@')},"
                         f"{rng.choice(['admin','editor','viewer','billing'])},"
                         f"2026-{rng.randint(1,5):02d}-{rng.randint(1,28):02d}T"
                         f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:00Z,"
                         f"{rng.choice(['true','false'])}")
        return ("\n".join(rows) + "\n").encode()

    def _build_financials_csv(self) -> bytes:
        rng = self._rng
        rows = ["month,revenue_usd,refunds_usd,net_usd"]
        for m in range(1, 13):
            rev = rng.randint(180000, 540000)
            ref = rng.randint(2000, 18000)
            rows.append(f"2025-{m:02d},{rev},{ref},{rev-ref}")
        return ("\n".join(rows) + "\n").encode()

    def _build_api_log_csv(self) -> bytes:
        rng = self._rng
        rows = ["ts,path,status,latency_ms,user"]
        for i in range(40):
            rows.append(f"2025-10-{rng.randint(1,30):02d}T"
                         f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}Z,"
                         f"/api/v1/{rng.choice(['payments','customers','invoices','reports'])}/"
                         f"{rng.randint(1000,9999)},"
                         f"{rng.choice([200,200,200,200,401,403,404,500])},"
                         f"{rng.randint(15,840)},"
                         f"{self.v['customers'][rng.randint(0, len(self.v['customers'])-1)]['email']}")
        return ("\n".join(rows) + "\n").encode()

    # ---------- HTML canary builder ----------
    def _build_html_canary(self, download_id: str) -> bytes:
        token = secrets.token_urlsafe(12)
        beacon = (f"{self.canary_base}/{self.agent}/{download_id}/{token}.png"
                   if self.canary_base else f"about:blank#{token}")
        v = self.v
        body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Internal Status Report — {html.escape(v['org_short'])}</title>
  <style>
    body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 2em; color: #222; max-width: 780px; }}
    h1 {{ border-bottom: 2px solid #444; padding-bottom: 0.3em; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ text-align: left; padding: 6px 12px; border-bottom: 1px solid #ddd; }}
    .confidential {{ color: #c33; font-weight: bold; }}
  </style>
</head>
<body>
  <p class="confidential">CONFIDENTIAL — Internal Distribution Only</p>
  <h1>Q1 2026 Status Report</h1>
  <p>Prepared by {html.escape(v['ops_full'])} ({html.escape(v['ops_email'])}).</p>

  <h2>Infrastructure</h2>
  <ul>
    <li>Production cluster: <code>k8s-prod.{html.escape(v['int_domain'])}</code></li>
    <li>Database master: <code>db-prod-01.{html.escape(v['int_domain'])}</code></li>
    <li>Vault: <code>vault.{html.escape(v['int_domain'])}:8200</code></li>
    <li>Bastion: <code>bastion.{html.escape(v['int_domain'])}:22</code></li>
  </ul>

  <h2>Customer Growth</h2>
  <table>
    <tr><th>Plan</th><th>Customers</th></tr>
    <tr><td>Enterprise</td><td>{sum(1 for c in v['customers'] if c['plan']=='enterprise')}</td></tr>
    <tr><td>Growth</td><td>{sum(1 for c in v['customers'] if c['plan']=='growth')}</td></tr>
    <tr><td>Starter</td><td>{sum(1 for c in v['customers'] if c['plan']=='starter')}</td></tr>
  </table>

  <h2>Notes</h2>
  <p>Stripe webhook secret rotated: <code>whsec_{html.escape(v['stripe_whsec'][:16])}…</code></p>
  <p>Admin API token (do not commit): <code>{html.escape(v['admin_token'][:20])}…</code></p>

  <p style="margin-top:2em; color:#888; font-size:0.85em;">
    <img src="{html.escape(beacon)}" width="1" height="1" alt="" />
    Document ID: {html.escape(download_id)}
  </p>
</body>
</html>"""
        return body.encode("utf-8")


# ============================================================ apache-style autoindex
def _autoindex(path: str, entries: list[tuple[str, datetime, int, bool]]) -> str:
    """Render an Apache mod_autoindex HTML page for `path`."""
    rows = []
    if path != "/":
        rows.append(
            '<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td>'
            f'<td><a href="../">Parent Directory</a></td>'
            '<td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>'
        )
    for name, mtime, size, is_dir in entries:
        if is_dir:
            icon = "folder.gif"
            alt = "[DIR]"
            href = name + "/"
            size_s = "  - "
        else:
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            icon = {
                "gz": "compressed.gif", "tgz": "compressed.gif", "tar": "compressed.gif",
                "zip": "compressed.gif", "sql": "text.gif", "csv": "text.gif",
                "txt": "text.gif", "md": "text.gif", "log": "text.gif",
                "html": "layout.gif", "htm": "layout.gif",
                "pdf": "pdf.gif",
                "docx": "binary.gif", "xlsx": "binary.gif",
                "key": "text.gif", "crt": "text.gif", "pem": "text.gif",
                "json": "text.gif", "yaml": "text.gif", "yml": "text.gif",
                "env": "text.gif",
            }.get(ext, "binary.gif")
            alt = "[   ]"
            href = name
            size_s = _format_size(size)
        ts = mtime.strftime("%Y-%m-%d %H:%M")
        rows.append(
            f'<tr><td valign="top"><img src="/icons/{icon}" alt="{alt}"></td>'
            f'<td><a href="{html.escape(href)}">{html.escape(name)}</a></td>'
            f'<td align="right">{ts}  </td>'
            f'<td align="right">{size_s}</td><td>&nbsp;</td></tr>'
        )

    return f"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of {html.escape(path)}</title>
 </head>
 <body>
<h1>Index of {html.escape(path)}</h1>
<table>
<tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th>
<th><a href="?C=N;O=D">Name</a></th>
<th><a href="?C=M;O=A">Last modified</a></th>
<th><a href="?C=S;O=A">Size</a></th>
<th><a href="?C=D;O=A">Description</a></th></tr>
<tr><th colspan="5"><hr></th></tr>
{chr(10).join(rows)}
<tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at {html.escape(request.host)} Port {request.environ.get("SERVER_PORT", "80")}</address>
</body></html>
"""


def _format_size(n: int) -> str:
    if n < 1024:
        return f"{n:>4d} "
    for unit in ("K", "M", "G", "T"):
        n /= 1024
        if n < 1024:
            return f"{n:>4.1f}{unit}"
    return f"{n:>4.1f}P"


# ============================================================ routes
@app.route("/", methods=["GET", "HEAD"])
@app.route("/<path:path>", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"])
def serve_path(path: str = ""):
    share = _get_share()
    norm = "/" + path.strip("/") if path else "/"

    # Trailing-slash directory access
    if request.path.endswith("/") and share.has_dir(norm):
        return _serve_dir(share, norm)
    if share.has_dir(norm):
        # Add trailing slash (real apache does 301)
        return make_response("", 301, {"Location": norm + "/"})

    # Files
    if share.has_file(norm):
        return _serve_file(share, norm)

    # Common scanner-bait paths — return what attackers expect
    return _scanner_responses(norm)


def _serve_dir(share: FileShare, path: str):
    # If an index.html exists at this dir, serve it instead of the listing
    idx = (path.rstrip("/") + "/index.html") if path != "/" else "/index.html"
    if share.has_file(idx) and request.args.get("autoindex") != "1":
        return _serve_file(share, idx)

    entries = share.list_dir(path)
    body = _autoindex(path, entries)
    return make_response(body, 200, {"Content-Type": "text/html; charset=utf-8"})


def _serve_file(share: FileShare, path: str):
    download_id = str(uuid.uuid4())

    if share.is_canary(path):
        # Log a stronger event so the operator can correlate beacon hits back here
        _log_request(EventType.HTTP_REQUEST, {
            "canary_event": "canary_file_downloaded",
            "file": path,
            "download_id": download_id,
        })

    try:
        data, mime, mtime = share.read(path, download_id=download_id)
    except FileNotFoundError:
        return make_response("Not Found", 404)

    # HEAD vs GET
    if request.method == "HEAD":
        resp = make_response("", 200)
    else:
        resp = make_response(data, 200)
    resp.headers["Content-Type"] = mime
    resp.headers["Content-Length"] = str(len(data))
    resp.headers["Last-Modified"] = mtime.strftime("%a, %d %b %Y %H:%M:%S GMT")
    # Force download for binary-ish things to look legit
    base = path.rsplit("/", 1)[-1]
    if mime.startswith(("application/", "text/csv", "application/sql")):
        if not any(base.endswith(ext) for ext in (".html", ".json", ".yaml", ".yml")):
            resp.headers["Content-Disposition"] = f'attachment; filename="{base}"'
    return resp


def _scanner_responses(path: str):
    """Realistic 404/403/redirects for common scanner paths so we still get probed."""
    low = path.lower()

    # Apache server-status — only allow from localhost
    if low in ("/server-status", "/server-info"):
        return make_response("<h1>Forbidden</h1>", 403)

    # WordPress paths — pretend it's a wp site
    if low in ("/wp-login.php", "/wp-admin/", "/wp-admin"):
        return make_response(_WP_LOGIN_HTML, 200, {"Content-Type": "text/html; charset=utf-8"})

    # phpMyAdmin
    if low in ("/phpmyadmin/", "/phpmyadmin", "/pma/", "/pma"):
        return make_response(_PMA_LOGIN_HTML, 200, {"Content-Type": "text/html; charset=utf-8"})

    # /admin login (captures POST creds)
    if low == "/admin" or low == "/admin/":
        if request.method == "POST":
            form = request.form
            username = form.get("username") or form.get("user") or form.get("email") or ""
            password = form.get("password") or form.get("pass") or form.get("passwd") or ""
            _log_request(EventType.HTTP_LOGIN, {
                "username": username,
                "password": password,
                "form_keys": list(form.keys()),
            })
            time.sleep(0.4)
            return make_response(_ADMIN_LOGIN_HTML.replace("__ERROR__",
                                  "<p style='color:#c33'>Invalid credentials.</p>"),
                                 401, {"Content-Type": "text/html; charset=utf-8"})
        return make_response(_ADMIN_LOGIN_HTML.replace("__ERROR__", ""),
                             200, {"Content-Type": "text/html; charset=utf-8"})

    # .well-known
    if low == "/.well-known/security.txt":
        share = _get_share()
        return make_response(
            f"Contact: mailto:security@{share.v['ext_domain']}\n"
            f"Preferred-Languages: en\nExpires: 2027-01-01T00:00:00.000Z\n",
            200, {"Content-Type": "text/plain"})

    # Plain 404 for everything else
    return make_response(_APACHE_404, 404, {"Content-Type": "text/html; charset=utf-8"})


# ============================================================ static templates
_ROOT_INDEX_HTML = """\
<!DOCTYPE html>
<html><head><title>{org_short} — Internal File Share</title>
<style>body{{font-family:sans-serif;margin:2em;max-width:780px}}</style>
</head><body>
<h1>{org_short} Internal File Share</h1>
<p>This server hosts internal documents, database backups, and exports.
Intended for staff use only. Authorised personnel only.</p>
<ul>
  <li><a href="/backups/">Database backups</a></li>
  <li><a href="/docs/">Documentation</a></li>
  <li><a href="/exports/">Customer / financial exports</a></li>
  <li><a href="/uploads/invoices/">Invoices</a></li>
  <li><a href="/admin/">Administration</a></li>
</ul>
<p><small>Contact: <a href="mailto:ops@{ext_domain}">ops@{ext_domain}</a></small></p>
</body></html>
"""

_README_TXT = """\
{org_short} internal file share
================================

Hosted on host {host}. Maintained by {ops_full} ({ops_email}).

Layout:
  /backups/   nightly database dumps
  /docs/      operational runbooks and architecture
  /exports/   customer + financial CSV exports
  /private/   restricted (htaccess), do not link from public pages
  /uploads/   invoice PDFs

Rotation: backups older than 90 days are pruned by /etc/cron.d/backups.
"""

_ROBOTS_TXT = """\
User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /backups/
Disallow: /.git/
Disallow: /exports/
Disallow: /api/v1/internal/
Disallow: /uploads/invoices/
"""

_ENV_FILE = """\
# /opt/app/.env
NODE_ENV=production
DATABASE_URL=postgres://payments:{db_pass}@db-prod-01.{int_domain}:5432/billing
REDIS_URL=redis://:{redis_pass}@redis-prod.{int_domain}:6379/0
STRIPE_SECRET_KEY=sk_live_{stripe_key}
STRIPE_WEBHOOK_SECRET=whsec_{stripe_whsec}
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID={aws_key}
AWS_SECRET_ACCESS_KEY={aws_secret}
S3_BUCKET={org_short}-payments-prod
JWT_SECRET={jwt_secret}
ADMIN_API_URL=https://internal-admin.{ext_domain}/api
ADMIN_API_TOKEN={admin_token}
SLACK_WEBHOOK=https://hooks.slack.com/services/T08{slack_t}/B05{slack_b}/{slack_k}
"""

_HTACCESS = """\
# Apache config
Options +Indexes -MultiViews
IndexOptions FancyIndexing HTMLTable SuppressDescription IconsAreLinks NameWidth=*
DirectoryIndex index.html

<FilesMatch "^\\.(env|git|htaccess)">
  Require all granted
</FilesMatch>
"""

_GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://x-access-token:{github_pat}@github.com/{org_short}/payments-api.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = {ops_full}
\temail = {ops_email}
"""

_SQL_PREVIEW = """\
-- last db backup (preview) — full dump in db_backup_YYYY-MM-DD.sql.gz
SET statement_timeout = 0;
SET client_encoding = 'UTF8';

CREATE TABLE customers (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    name character varying(255),
    company character varying(255),
    plan character varying(64),
    monthly_value_usd integer,
    signup_date date,
    country char(2)
);

CREATE TABLE api_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token_hash character varying(255) NOT NULL,
    created_at timestamp,
    last_used_at timestamp,
    scope character varying(255)
);

INSERT INTO api_tokens (id, user_id, token_hash, created_at, last_used_at, scope) VALUES
 (1, 1, 'sha256:{db_pass}', '2024-01-15 09:30:00', '2026-05-25 17:42:00', 'admin'),
 (2, 1, 'sha256:{db_pass2}', '2024-01-20 14:15:00', '2026-05-26 09:01:00', 'read');

-- (file truncated — full dump available via tarball)
"""

_RUNBOOK_MD = """\
# {org_short} ops runbook

## Daily

  - check `#alerts` slack
  - https://metrics.{int_domain}/d/payments
  - tail nginx errors: `ssh bastion -- 'tail -F /var/log/nginx/api.error.log'`

## Common operations

### Restart payments-api
    kubectl --context production rollout restart deployment/payments-api -n payments

### Restore from backup
    aws s3 cp s3://{org_short}-prod-backups/db/db_backup_YYYY-MM-DD.sql.gz /tmp/
    gunzip -d /tmp/db_backup_*.sql.gz
    psql -h db-prod-01.{int_domain} -U postgres billing < /tmp/db_backup_*.sql

### Rotate API key
  1. mint new key: `vault write secret/payments/api-key`
  2. update k8s secret
  3. roll deployment: `kubectl rollout restart deployment/payments-api`

## Contacts

  - on-call: @ops-oncall
  - db owner: {dba_full} ({dba_email})
  - sec: secops@{ext_domain}
"""

_ARCH_MD = """\
# Architecture

## Components

- `payments-api` (Node.js) — public-facing api
- `payments-worker` (Python) — async job processor
- `billing-cron` (Python) — invoice generation, runs hourly
- PostgreSQL 15 on `db-prod-01.{int_domain}` (master), `db-prod-02.{int_domain}` (replica)
- Redis 7 on `redis-prod.{int_domain}`

## Internal endpoints

| service | URL |
|---|---|
| Grafana | https://metrics.{int_domain} |
| Sentry | https://sentry.{int_domain} |
| Vault | https://vault.{int_domain}:8200 |
| Internal admin | https://internal-admin.{ext_domain} |

## Network

- Bastion: `bastion.{int_domain}` (only ingress from corp VPN)
- Production VPC: 10.10.0.0/16
- All east-west traffic over service mesh (mTLS, istio)
"""

_ONBOARDING_MD = """\
# New employee onboarding — engineering

Welcome to {org_short}.

## Day 1 setup

  1. Get your SSO from {ops_email}.
  2. Install 1Password from https://{org_short}.1password.com
  3. Pull your AWS console role: production / read-only by default.
     Ask {ops_first} to elevate when you start on-call.
  4. Generate your VPN cert with the script at /opt/scripts/vpn-issue.sh
     on bastion. Cert lives at /etc/openvpn/client/<you>.ovpn.
  5. Clone the main repo: `git clone https://github.com/{org_short}/payments-api`
  6. Join `#engineering`, `#alerts`, `#incidents` on Slack.

## Read this

  - /docs/runbook.md
  - /docs/architecture.md
"""

_CREDENTIALS_TXT = """\
# DO NOT COMMIT — local notes for migration

postgres master       host=db-prod-01.{int_domain}  user=postgres  pass={db_pass}
postgres replica      host=db-prod-02.{int_domain}  user=postgres  pass={db_pass2}
redis                 host=redis-prod.{int_domain}  pass={redis_pass}
vault root token      {vault_token}
admin api token       {admin_token}
github pat ({ops_first})  {github_pat}
stripe secret         sk_live_{stripe_key}
stripe webhook sec    whsec_{stripe_whsec}
aws prod              {aws_key2} / {aws_secret2}
aws backup (eu-west)  {aws_key3} / {aws_secret3}
slack webhook         https://hooks.slack.com/services/T08{slack_t}/B05{slack_b}/{slack_k}
datadog               {dd_key}

(rotation due Q3; tracker ticket OPS-2241)
"""

_AWS_ROTATION_TXT = """\
AWS key rotation log

== {today} ==
- minted new default profile key: {aws_key}
- old key tagged for deletion at +30d
- updated /opt/app/.env on prod hosts (3)
- ticket OPS-2241

== {last_rotated} ==
- rotated backup profile key (eu-west-1)
- new: {aws_key3}
- updated terraform.tfvars in main repo

== prior ==
- backup profile created 2024-01-12
"""

_PRIVATE_KEY = """\
-----BEGIN PRIVATE KEY-----
{cert_filler3}
-----END PRIVATE KEY-----
"""

_CERTIFICATE = """\
-----BEGIN CERTIFICATE-----
{cert_filler}
-----END CERTIFICATE-----
"""

_OPENAPI_JSON = """\
{{
  "openapi": "3.0.0",
  "info": {{
    "title": "{org_short} payments API",
    "version": "2.14.3",
    "contact": {{ "email": "api@{ext_domain}" }}
  }},
  "servers": [
    {{ "url": "https://api.{ext_domain}/v1" }},
    {{ "url": "https://internal-admin.{ext_domain}/api/v1" }}
  ],
  "paths": {{
    "/payments/{{id}}": {{ "get": {{ "summary": "Get a payment by id" }} }},
    "/customers/{{id}}": {{ "get": {{ "summary": "Get a customer" }} }},
    "/admin/users": {{ "get": {{ "summary": "List admin users (requires admin scope)" }} }},
    "/admin/keys": {{ "get": {{ "summary": "List API keys" }} }}
  }},
  "security": [{{ "bearerAuth": [] }}]
}}
"""

_WP_LOGIN_HTML = """\
<!DOCTYPE html>
<html><head><title>Log In &lsaquo; WordPress</title></head>
<body><div id="login"><form><label>Username<br><input name="log"></label><br>
<label>Password<br><input type="password" name="pwd"></label><br>
<input type="submit" value="Log In"></form></div></body></html>
"""

_PMA_LOGIN_HTML = """\
<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head>
<body><h1>Welcome to phpMyAdmin</h1>
<form><label>Username <input name="pma_username"></label><br>
<label>Password <input type="password" name="pma_password"></label><br>
<input type="submit" value="Go"></form></body></html>
"""

_ADMIN_LOGIN_HTML = """\
<!DOCTYPE html>
<html><head><title>Admin Login</title>
<style>body{font-family:sans-serif;margin:4em auto;max-width:380px}
input{width:100%;padding:8px;margin-bottom:8px;border:1px solid #ccc}
button{padding:8px 16px}</style></head>
<body><h2>Sign in</h2>
__ERROR__
<form method="POST">
<label>Username <input name="username"></label>
<label>Password <input type="password" name="password"></label>
<button type="submit">Sign in</button>
</form></body></html>
"""

_APACHE_404 = """\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server</address>
</body></html>
"""


# ============================================================ runner
def serve(host: str = "0.0.0.0", http_port: int = 80, https_port: int = 443) -> None:
    import threading
    cfg = Config.load()
    L.configure(cfg.log_dir, cfg.node_name, "fileshare")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "fileshare_sensor",
                       "http_port": http_port, "https_port": https_port})

    # warm the share state
    _get_share()

    cert = Path(cfg.data_dir) / "share.crt"
    key  = Path(cfg.data_dir) / "share.key"

    def _run_http():
        from werkzeug.serving import make_server
        s = make_server(host, http_port, app, threaded=True)
        s.serve_forever()

    def _run_https():
        from werkzeug.serving import make_server
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        s = make_server(host, https_port, app, threaded=True, ssl_context=ctx)
        s.serve_forever()

    t1 = threading.Thread(target=_run_http,  daemon=True)
    t2 = threading.Thread(target=_run_https, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()


if __name__ == "__main__":
    serve()
