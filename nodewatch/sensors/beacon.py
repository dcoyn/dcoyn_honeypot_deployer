"""
nodewatch.sensors.beacon
=========================

A tiny, always-on **canary beacon receiver** so that *every* deployment can
catch the callback when an attacker opens a bait document — not just the
fileshare profile.

The fileshare sensor already serves HTTP on 80/443 and has the beacon route
built in. The other profiles (ssh, telnet, redis, winserver) don't speak HTTP,
so on those boxes the runner starts this minimal listener on 80/443 alongside
the real sensor. owa already serves HTTP, so it installs the same intercept on
its own app instead (see ``install_beacon_intercept``).

This module does NOT serve any fake files — it only catches beacons and returns
a bland Apache 404 for everything else. All the heavy lifting (NTLM handshake,
downloader↔opener correlation, proxy unmasking, opener classification) is the
exact same code path the fileshare sensor uses; we just reuse those handlers so
behaviour is identical everywhere and there's one implementation to maintain.

Because ``HP_CANARY_URL`` is auto-pointed at the deploying host, a canary opened
anywhere beacons straight back to the same honeypot with zero extra config.
"""
from __future__ import annotations

import os
import ssl
import subprocess
import threading
from pathlib import Path

from flask import Flask, request, make_response

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from . import fileshare_sensor as FS


# ---------------------------------------------------------------------------
# The intercept: identical logic to the fileshare sensor's beacon handling.
# Returns a Response on a beacon hit (caller should short-circuit), or None.
# ---------------------------------------------------------------------------
def _beacon_response():
    dav = FS._DAV_PATH_RE.match(request.path)
    if dav:
        return FS._handle_dav_beacon(dav)
    m = FS._BEACON_PATH_RE.match(request.path)
    if m:
        return FS._handle_canary_beacon(m)
    return None


def install_beacon_intercept(app: Flask) -> None:
    """Add beacon catching to an existing HTTP sensor app (e.g. owa).

    Runs before the host app's own handlers; only short-circuits on a beacon
    path, otherwise returns None so the host app responds and logs as usual.
    """
    @app.before_request
    def _maybe_beacon():            # noqa: ANN202 (flask hook)
        return _beacon_response()


# ---------------------------------------------------------------------------
# Standalone listener (for non-HTTP profiles)
# ---------------------------------------------------------------------------
beacon_app = Flask("nodewatch-beacon")


@beacon_app.before_request
def _intercept():                  # noqa: ANN202
    resp = _beacon_response()
    if resp is not None:
        return resp
    # Not a beacon — record the poke (this host's IP is known to attackers who
    # downloaded a bait file) and return a believable Apache 404.
    try:
        FS._log_request(EventType.HTTP_REQUEST, {"beacon_receiver": True})
    except Exception:
        pass
    return make_response("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
                         "<html><head><title>404 Not Found</title></head>"
                         "<body><h1>Not Found</h1></body></html>",
                         404, {"Content-Type": "text/html; charset=iso-8859-1",
                               "Server": "Apache/2.4.41 (Ubuntu)"})


def _ensure_cert(cfg) -> tuple[Path, Path] | None:
    """Find or best-effort generate a self-signed cert for the HTTPS listener.
    Beacons default to http://, so HTTPS is a bonus — never fatal if missing."""
    data = Path(cfg.data_dir)
    for stem in ("share", "owa", "beacon"):
        crt, key = data / f"{stem}.crt", data / f"{stem}.key"
        if crt.exists() and key.exists():
            return crt, key
    crt, key = data / "beacon.crt", data / "beacon.key"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
             "-keyout", str(key), "-out", str(crt), "-days", "825",
             "-subj", "/CN=intranet"],
            check=True, capture_output=True, timeout=30)
        return crt, key
    except Exception:
        return None


def serve(host: str = "0.0.0.0", http_port: int = 80, https_port: int = 443,
          role: str = "beacon") -> None:
    """Bind the beacon receiver on 80 (primary) and 443 (best-effort TLS).
    Each port binds independently; a port already in use is skipped, never
    fatal. Blocks forever (run me in a thread)."""
    from werkzeug.serving import make_server
    from ..core.http_stealth import StealthWSGIRequestHandler

    cfg = Config.load()
    # Rely on the co-resident sensor having configured logging; L.get() also
    # falls back to env config, so a bare beacon process still logs correctly.
    try:
        L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                     data={"role": "beacon_receiver",
                           "http_port": http_port, "https_port": https_port})
    except Exception:
        pass

    servers = []

    def _try(port: int, ctx=None):
        try:
            s = make_server(host, port, beacon_app, threaded=True, ssl_context=ctx,
                            request_handler=StealthWSGIRequestHandler)
            servers.append(threading.Thread(target=s.serve_forever, daemon=True,
                                             name=f"beacon-{port}"))
        except Exception as e:  # port taken / perm denied → skip, don't crash
            print(f"beacon receiver: skipping port {port}: {e}")

    _try(http_port)
    cert = _ensure_cert(cfg)
    if cert:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert[0]), keyfile=str(cert[1]))
            _try(https_port, ctx)
        except Exception as e:
            print(f"beacon receiver: TLS disabled: {e}")

    if not servers:
        print("beacon receiver: no ports bound; canary opens won't be captured")
        return
    for t in servers:
        t.start()
    for t in servers:
        t.join()


if __name__ == "__main__":
    serve()
