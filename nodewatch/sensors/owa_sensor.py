"""
sensors.owa_sensor
===============================

Fake Microsoft Outlook Web Access landing page for a *fictitious*
company. The point is to attract credential-spray and AiTM toolkits
and log everything they send.

Important design decisions:
  * We never use real company branding. The company is "Northbridge
    Logistics" — a name we made up. Using a real company's logo would
    make this a phishing kit instead of a defensive sensor.
  * The page is a static-ish HTML clone of the OWA layout style with
    placeholder branding; functional bits (form, JS) are minimal.
  * Every POST is recorded but always responds with "incorrect
    password". Attackers think they're harvesting nothing useful, we
    keep collecting.
  * Headers, cookies, body, JA3/JA4 (provided by the packet capture
    sidecar) all flow into the central event log.

Runs as gunicorn behind nothing — it terminates TLS itself, because
we want to be the source of fingerprints (no reverse proxy strips
them) and we want to log connection errors too.
"""
from __future__ import annotations

import base64
import ssl
import time
from pathlib import Path
from typing import Optional

from flask import Flask, request, render_template, redirect, url_for, make_response, abort

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich


COMPANY = "Northbridge Logistics"   # invented, not a real company
DOMAIN  = "northbridge-logistics.com"

app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent.parent.parent / "templates"),
)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # 256kB max body


def _log_request(event_type: str, extra: Optional[dict] = None):
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()
    src_port = 0  # not exposed by WSGI
    sid = TRACKER.get(src_ip)

    headers = {k: v for k, v in request.headers.items()}
    # truncate gigantic headers
    headers = {k: (v[:2048] if isinstance(v, str) else v) for k, v in headers.items()}

    body_b64 = ""
    body_len = 0
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
        src_ip=src_ip, src_port=src_port, dst_port=request.environ.get("SERVER_PORT", 443),
        session_id=sid,
        data=data,
        sensor_profile="owa",
    )


@app.before_request
def _trace():
    request.environ["_HP_T0"] = time.monotonic()
    _log_request(EventType.HTTP_REQUEST)


@app.after_request
def _latency(resp):
    t0 = request.environ.get("_HP_T0")
    if t0:
        resp.headers["X-Response-Time-Ms"] = str(int((time.monotonic() - t0) * 1000))
    # Microsoft-flavored response headers to look more real
    resp.headers["Server"] = "Microsoft-IIS/10.0"
    resp.headers["X-Powered-By"] = "ASP.NET"
    resp.headers["X-AspNet-Version"] = "4.0.30319"
    return resp


# ----------------------------------------------------------------- routes
@app.route("/", methods=["GET"])
@app.route("/owa", methods=["GET"])
@app.route("/owa/", methods=["GET"])
@app.route("/owa/auth/logon.aspx", methods=["GET"])
def login_page():
    resp = make_response(render_template("owa_login.html",
                                         company=COMPANY, domain=DOMAIN))
    # Plant a tracking cookie so we can correlate within a session
    if "OWA-SID" not in request.cookies:
        resp.set_cookie("OWA-SID", L.get().new_session(), httponly=True, secure=True)
    return resp


@app.route("/owa/auth.owa", methods=["POST"])
@app.route("/owa/auth/logon.aspx", methods=["POST"])
@app.route("/owa/login", methods=["POST"])
def login_post():
    form = request.form
    username = form.get("username") or form.get("user") or form.get("email") or ""
    password = form.get("password") or form.get("pass") or form.get("passwd") or ""
    _log_request(EventType.HTTP_LOGIN, {
        "username": username,
        "password": password,
        "form_keys": list(form.keys()),
    })
    # Always fail — but slowly, so timing-side-channel sniffers are happy
    time.sleep(0.4)
    resp = make_response(render_template(
        "owa_error.html",
        company=COMPANY, domain=DOMAIN,
        message="The user name or password you entered isn't correct. Try entering it again."
    ), 401)
    return resp


# Catch-all to log spidering / vuln scanning attempts
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
def catch_all(path):
    # Pretend to be IIS with these well-known paths
    if path.lower() in ("autodiscover/autodiscover.xml", "ecp/", "owa/"):
        return redirect(url_for("login_page"))
    return make_response(f"<html><body><h1>404 - Not Found</h1></body></html>", 404)


# ----------------------------------------------------------------- runner
def serve(host: str = "0.0.0.0", http_port: int = 80, https_port: int = 443) -> None:
    """Spin up both 80 and 443; 443 gets the self-signed cert."""
    import threading

    cfg = Config.load()
    L.configure(cfg.log_dir, cfg.node_name, "owa")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "owa_sensor",
                       "http_port": http_port, "https_port": https_port,
                       "company": COMPANY})

    cert = Path(cfg.data_dir) / "owa.crt"
    key  = Path(cfg.data_dir) / "owa.key"

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
