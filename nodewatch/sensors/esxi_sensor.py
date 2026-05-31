"""
sensors.esxi_sensor
===================

A medium-interaction **VMware ESXi** honeypot on port 443 (HTTPS).

Exposed ESXi hosts are a top ransomware target: the ESXiArgs, Akira, Royal and
Black Basta crews all hunt for them, encrypt the VMFS datastores, and ransom the
whole virtualization estate at once. Scanners fingerprint ESXi constantly via
its SOAP API and Host Client.

We present a believable ESXi 7.0.x host:

  * ``GET /``        → the ESXi "Welcome" landing page (VMware branding, version)
  * ``GET /ui/``     → the Host Client shell
  * ``POST /sdk``    → the vSphere SOAP API. We answer ``RetrieveServiceContent``
                       with a realistic ServiceContent (version/build/apiVersion)
                       so fingerprinting scanners are satisfied, and we
                       **capture the credentials** from every ``Login`` SOAP call
                       (username + password in the body) before returning an
                       "invalid login" fault so they keep trying.
  * ``/folder``      → the datastore browser (prompts for auth)

Known scanner/exploit probe paths are flagged. Nothing is real — there is no
hypervisor, no datastore, no session; it's all believable theatre that records
who is hunting ESXi hosts and what credentials they bring.

Note: the headline ESXi CVE (CVE-2021-21974) is in OpenSLP on UDP/427, not the
HTTP surface; this sensor covers the 443 attack surface where login attempts and
SOAP fingerprinting happen. The catch-all SYN logger still records 427 probes.
"""
from __future__ import annotations

import re
import secrets

from flask import Flask, request, Response, make_response

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich
from ..core import threat_intel as TI

LISTEN_PORT = 443
ESXI_VERSION = "7.0.3"
ESXI_BUILD = "19898904"
ESXI_FULLNAME = f"VMware ESXi {ESXI_VERSION} build-{ESXI_BUILD}"
ESXI_API_VERSION = "7.0.3.0"

app = Flask("nodewatch-esxi")

_SOAP_USER_RE = re.compile(r"<userName>(.*?)</userName>", re.I | re.S)
_SOAP_PASS_RE = re.compile(r"<password>(.*?)</password>", re.I | re.S)
_SOAP_BODY_RE = re.compile(r"<(?:\w+:)?(\w+)[ >]", re.S)

# Scanner / exploit probe paths worth flagging.
_SUSPICIOUS_PATHS = (
    "/sdk", "/folder", "/cgi-bin", "/health.json", "/ui/login",
    "../", "..%2f", "%2e%2e", "/mob", "/sdk/vimServiceVersions.xml",
)


def _client_ip() -> str:
    return (request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
            .split(",")[0].strip())


def _log(event_type, data: dict) -> None:
    src_ip = _client_ip()
    try:
        L.get().emit(event_type, src_ip=src_ip,
                     src_port=int(request.environ.get("REMOTE_PORT", 0) or 0),
                     dst_port=LISTEN_PORT, session_id=TRACKER.get(src_ip), data=data)
    except Exception:
        pass


def _soap(body: str, status: int = 200) -> Response:
    resp = make_response(body, status)
    resp.headers["Content-Type"] = 'text/xml; charset="utf-8"'
    return resp


_WELCOME_HTML = f"""<!DOCTYPE html><html><head><title>VMware ESXi</title>
<meta http-equiv="refresh" content="0; URL=/ui/"></head>
<body><div id="esxi-welcome">
<h1>VMware ESXi {ESXI_VERSION}</h1>
<p>Welcome. To manage this host, open the <a href="/ui/">VMware Host Client</a>.</p>
<ul>
<li><a href="/ui/">Open the VMware Host Client</a></li>
<li><a href="https://www.vmware.com/go/download-vsphere">Download vSphere</a></li>
</ul>
<p>For more information, see the documentation for VMware vSphere.</p>
</div></body></html>"""

_UI_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>VMware ESXi Host Client</title>
<link rel="icon" href="/ui/favicon.ico"></head>
<body><div id="root"><noscript>The VMware Host Client requires JavaScript.</noscript></div>
<script src="/ui/scripts/main.js"></script></body></html>"""


def _service_content() -> str:
    inst = secrets.token_hex(8)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<soapenv:Body>
<RetrieveServiceContentResponse xmlns="urn:vim25">
<returnval>
<rootFolder type="Folder">ha-folder-root</rootFolder>
<propertyCollector type="PropertyCollector">ha-property-collector</propertyCollector>
<about>
<name>VMware ESXi</name>
<fullName>{ESXI_FULLNAME}</fullName>
<vendor>VMware, Inc.</vendor>
<version>{ESXI_VERSION}</version>
<build>{ESXI_BUILD}</build>
<localeVersion>INTL</localeVersion>
<localeBuild>000</localeBuild>
<osType>vmnix-x86</osType>
<productLineId>embeddedEsx</productLineId>
<apiType>HostAgent</apiType>
<apiVersion>{ESXI_API_VERSION}</apiVersion>
<licenseProductName>VMware ESX Server</licenseProductName>
<licenseProductVersion>7.0</licenseProductVersion>
<instanceUuid>{inst}</instanceUuid>
</about>
<sessionManager type="SessionManager">ha-sessionmgr</sessionManager>
</returnval>
</RetrieveServiceContentResponse>
</soapenv:Body></soapenv:Envelope>"""


_INVALID_LOGIN_FAULT = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<soapenv:Body><soapenv:Fault>
<faultcode>ServerFaultCode</faultcode>
<faultstring>Cannot complete login due to an incorrect user name or password.</faultstring>
<detail><InvalidLoginFault xmlns="urn:vim25" xsi:type="InvalidLogin"></InvalidLoginFault></detail>
</soapenv:Fault></soapenv:Body></soapenv:Envelope>"""


def _esxi_headers(resp):
    # ESXi's rhttpproxy is sparing with headers; mimic that. The stealth WSGI
    # handler already suppresses any Werkzeug Server banner.
    resp.headers.pop("Server", None)
    return resp


@app.route("/", methods=["GET", "HEAD"])
def _root():
    _log(EventType.ESXI_REQUEST, {"path": "/", "method": request.method,
         "user_agent": request.headers.get("User-Agent", "")[:300],
         "geo": enrich(_client_ip())})
    return _esxi_headers(make_response(_WELCOME_HTML))


@app.route("/ui/", methods=["GET"])
@app.route("/ui/<path:_sub>", methods=["GET"])
def _ui(_sub=""):
    _log(EventType.ESXI_REQUEST, {"path": request.path[:200], "method": "GET",
         "user_agent": request.headers.get("User-Agent", "")[:300],
         "geo": enrich(_client_ip())})
    return _esxi_headers(make_response(_UI_HTML))


@app.route("/sdk", methods=["POST"])
@app.route("/sdk/", methods=["POST"])
@app.route("/sdk/vimService", methods=["POST"])
def _sdk():
    src_ip = _client_ip()
    geo = enrich(src_ip)
    try:
        body = request.get_data(cache=True)[:65536].decode("utf-8", "replace")
    except Exception:
        body = ""
    # Which SOAP operation? (first child of <Body>)
    op = ""
    soap_action = request.headers.get("SOAPAction", "").strip('"')
    m = re.search(r"<(?:\w+:)?Body[^>]*>\s*<(?:\w+:)?(\w+)", body, re.S)
    if m:
        op = m.group(1)

    _log(EventType.ESXI_REQUEST, {
        "path": request.path, "method": "POST", "soap_operation": op,
        "soap_action": soap_action[:200],
        "user_agent": request.headers.get("User-Agent", "")[:300],
        "geo": geo, "intel": TI.tag_event(src_ip, geo,
                                          user_agent=request.headers.get("User-Agent", "")),
    })

    # Credential capture on Login / LoginByToken / LoginExtensionByCertificate
    if op.lower().startswith("login"):
        user = _SOAP_USER_RE.search(body)
        pwd = _SOAP_PASS_RE.search(body)
        username = (user.group(1).strip() if user else "")[:256]
        password = (pwd.group(1).strip() if pwd else "")[:256]
        _log(EventType.ESXI_LOGIN, {
            "service": "esxi", "operation": op,
            "username": username, "password": password,
            "geo": geo, "intel": TI.tag_event(src_ip, geo),
            "techniques": ["T1110", "T1078"],  # Brute Force / Valid Accounts
        })
        return _esxi_headers(_soap(_INVALID_LOGIN_FAULT, status=500))

    if op in ("RetrieveServiceContent", "RetrieveServiceContentRequest"):
        return _esxi_headers(_soap(_service_content()))

    # Default: a generic but plausible empty success envelope.
    return _esxi_headers(_soap(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soapenv:Body></soapenv:Body></soapenv:Envelope>'))


@app.route("/sdk/vimServiceVersions.xml", methods=["GET"])
def _versions():
    _log(EventType.ESXI_REQUEST, {"path": request.path, "method": "GET",
         "soap_operation": "version_probe", "geo": enrich(_client_ip())})
    return _esxi_headers(_soap(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<namespaces version="1.0">'
        '<namespace><name>urn:vim25</name>'
        f'<version>{ESXI_API_VERSION}</version></namespace></namespaces>'))


@app.route("/folder", methods=["GET"])
@app.route("/folder/<path:_sub>", methods=["GET"])
def _folder(_sub=""):
    _log(EventType.ESXI_REQUEST, {"path": request.path[:200], "method": "GET",
         "event": "datastore_browse", "geo": enrich(_client_ip()),
         "techniques": ["T1083"]})
    resp = make_response("<html><head><title>401 Unauthorized</title></head>"
                         "<body>This method requires authentication.</body></html>", 401)
    resp.headers["WWW-Authenticate"] = 'Basic realm="VMware HTTP server"'
    return _esxi_headers(resp)


@app.route("/<path:rest>", methods=["GET", "POST", "HEAD", "PUT"])
def _catchall(rest):
    path = "/" + rest
    suspicious = any(tok in path.lower() for tok in _SUSPICIOUS_PATHS)
    _log(EventType.ESXI_REQUEST, {
        "path": path[:200], "method": request.method, "suspicious": suspicious,
        "user_agent": request.headers.get("User-Agent", "")[:300],
        "geo": enrich(_client_ip())})
    return _esxi_headers(make_response(
        "<html><head><title>404 Not Found</title></head>"
        "<body>The requested URL was not found on this server.</body></html>", 404))


def serve(host: str = "0.0.0.0", port: int = LISTEN_PORT) -> None:
    import ssl
    from pathlib import Path
    cfg = Config.load()
    if L._default is None:
        L.configure(cfg.log_dir, cfg.node_name, "esxi")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "esxi_sensor", "port": port,
                       "esxi_version": ESXI_VERSION})

    from werkzeug.serving import make_server
    from ..core.http_stealth import StealthWSGIRequestHandler

    cert = Path(cfg.data_dir) / "esxi.crt"
    key = Path(cfg.data_dir) / "esxi.key"
    if not (cert.exists() and key.exists()):
        # Best-effort self-signed generation (openssl is a hard dep of install.sh).
        try:
            import subprocess
            subprocess.run(
                ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                 "-keyout", str(key), "-out", str(cert), "-days", "730",
                 "-subj", "/CN=localhost.localdomain/O=VMware Installer"],
                check=True, capture_output=True, timeout=30)
        except Exception:
            pass

    ctx = None
    if cert.exists() and key.exists():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        except Exception:
            ctx = None
    s = make_server(host, port, app, threaded=True,
                    ssl_context=(ctx or "adhoc"),
                    request_handler=StealthWSGIRequestHandler)
    s.serve_forever()


if __name__ == "__main__":
    serve()
