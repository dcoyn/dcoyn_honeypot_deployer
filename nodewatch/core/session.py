"""
nodewatch.core.session
=====================

Cheap session ID assignment.

Sensors that have a clear protocol session (SSH) own their own IDs.
For stateless probes (a TCP SYN to port 445) we still want to group
events: we hand out the same session_id to events from the same src_ip
within a sliding window (default 5 min).
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict

WINDOW_SECONDS = 300


class IpSessionTracker:
    def __init__(self, window: int = WINDOW_SECONDS, max_entries: int = 100_000):
        self._lock = threading.Lock()
        self._table: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
        self._window = window
        self._max = max_entries

    def get(self, ip: str) -> str:
        now = time.time()
        with self._lock:
            entry = self._table.get(ip)
            if entry and (now - entry[1]) <= self._window:
                # refresh recency, keep the id
                sid = entry[0]
                self._table.move_to_end(ip)
                self._table[ip] = (sid, now)
                return sid
            sid = str(uuid.uuid4())
            self._table[ip] = (sid, now)
            self._table.move_to_end(ip)
            # bound memory
            while len(self._table) > self._max:
                self._table.popitem(last=False)
            return sid


# Module-global tracker so independent listeners share IDs
TRACKER = IpSessionTracker()
