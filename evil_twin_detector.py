"""
evil_twin_detector.py — Flags one SSID being broadcast by MORE THAN ONE
BSSID at the same time.

Unlike rogue_ap_detector.py (which needs you to pre-register your real
network), this one is general-purpose: it doesn't need any configuration
because it just watches for the pattern itself — legitimate networks
occasionally have multiple APs sharing an SSID on purpose (mesh WiFi,
enterprise setups with many access points), so this detector is tuned
to warn rather than assume malice, and includes both BSSIDs in the
alert so you can judge for yourself.
"""

import database
import alerts


class EvilTwinDetector:
    def __init__(self):
        # ssid -> set of BSSIDs we've seen broadcasting it
        self.seen = {}
        # Avoid re-alerting on every beacon once a pair is already flagged
        self._already_alerted = set()

    def handle(self, ssid, bssid):
        if not ssid:
            return  # ignore hidden/blank SSIDs, too noisy to be useful here

        bssid = bssid.lower()
        known_bssids = self.seen.setdefault(ssid, set())
        known_bssids.add(bssid)

        if len(known_bssids) > 1:
            pair_key = (ssid, frozenset(known_bssids))
            if pair_key in self._already_alerted:
                return
            self._already_alerted.add(pair_key)

            detail = (f"SSID '{ssid}' is being broadcast by multiple "
                       f"BSSIDs: {', '.join(sorted(known_bssids))}")
            alerts.raise_alert("Possible evil twin access point", detail)
            database.log_event(
                event_type="evil_twin",
                ssid=ssid,
                detail=detail,
            )
