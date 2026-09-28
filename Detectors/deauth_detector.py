"""
deauth_detector.py — Flags abnormal bursts of 802.11 deauth frames.

A single deauth frame is normal (devices disconnect all the time).
A BURST of them aimed at one BSSID in a short window is the signature
of an active deauth attack — usually done to force a device to
reconnect so its WPA handshake can be captured, or as a denial-of-service.
"""

import time
from collections import defaultdict

import configs
import database
import alerts


class DeauthDetector:
    def __init__(self):
        self.threshold = configs.DEAUTH_THRESHOLD
        self.window_seconds = configs.DEAUTH_WINDOW_SECONDS
        # bssid -> list of timestamps when a deauth was seen
        self.events = defaultdict(list)
        # Prevents spamming the same alert every single frame once
        # the threshold is already crossed within one window.
        self._already_alerted = set()

    def handle(self, bssid, source, target, reason):
        now = time.time()
        self.events[bssid].append(now)

        # Drop timestamps older than our rolling window.
        cutoff = now - self.window_seconds
        self.events[bssid] = [t for t in self.events[bssid] if t >= cutoff]

        count = len(self.events[bssid])

        if count >= self.threshold and bssid not in self._already_alerted:
            self._already_alerted.add(bssid)
            detail = (f"{count} deauth frames in {self.window_seconds}s "
                       f"(latest: {source} -> {target}, reason={reason})")
            alerts.raise_alert(
                "Possible deauth attack",
                f"BSSID {bssid} — {detail}",
            )
            database.log_event(
                event_type="deauth_burst",
                bssid=bssid,
                detail=detail,
            )
        elif count < self.threshold and bssid in self._already_alerted:
            # Window has cooled down — allow a fresh alert if it spikes again.
            self._already_alerted.discard(bssid)
