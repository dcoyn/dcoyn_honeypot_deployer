"""
nodewatch.core.http_stealth
============================

By default werkzeug's development WSGI server stamps a
``Server: Werkzeug/X Python/Y`` header (and a ``Date``) on every response.
For a honeypot that's a fatal tell — a scanner sees "Werkzeug" and knows the
"Apache" / "IIS" / "Docker" service in front of it is fake.

``StealthWSGIRequestHandler`` suppresses werkzeug's own ``Server`` header so the
only ``Server`` value sent is the realistic one each sensor app sets itself
(via an explicit header or an ``after_request`` hook). ``Date`` is still sent so
responses stay well-formed. Pass it to ``make_server(..., request_handler=...)``.

It also quiets the per-request stderr access log, which would otherwise spew
werkzeug's default logging to the journal.
"""
from __future__ import annotations

from werkzeug.serving import WSGIRequestHandler


class StealthWSGIRequestHandler(WSGIRequestHandler):
    # Reported to the WSGI app as SERVER_SOFTWARE; keep it generic, not Werkzeug.
    @property
    def server_version(self) -> str:   # type: ignore[override]
        return "Apache"

    sys_version = ""

    def send_response(self, code, message=None):
        """Send the status line + Date, but NOT a Server header — the app owns
        the Server header so it can impersonate Apache/IIS/Docker per response."""
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def log(self, type, message, *args):  # noqa: A002 (match base signature)
        # Suppress werkzeug's default access logging; the sensor does its own
        # structured event logging.
        pass
