"""
rogue_ap_detector.py — Flags a KNOWN/trusted SSID broadcasting from a
BSSID (MAC address) that doesn't match what you told NetworkEye to expect.

Configure your real networks in configs.TRUSTED_NETWORKS as
{ssid: real_bssid}. If NetworkEye ever sees, say, "MyHomeWiFi" coming
from a MAC address that ISN'T the one you registered, that's a strong
sign someone has stood up a rogue access point impersonating your network
— a common precursor to credential-harvesting or evil twin attacks.
"""

import configs
import database
import alerts


class RogueAPDetector:
    def __init__(self):
        # Normalize once for fast lookups: ssid -> expected bssid (lowercase)
        self.trusted = {
            ssid: bssid.lower()
            for ssid, bssid in configs.TRUSTED_NETWORKS.items()
        }
        # Avoid re-alerting every single beacon frame from the same rogue AP.
        self._already_alerted = set()

    def handle(self, ssid, bssid):
        if ssid not in self.trusted:
            return  # not one of our tracked networks, nothing to compare

        expected_bssid = self.trusted[ssid]
        seen_bssid = bssid.lower()

        if seen_bssid != expected_bssid:
            key = (ssid, seen_bssid)
            if key in self._already_alerted:
                return
            self._already_alerted.add(key)

            detail = (f"SSID '{ssid}' seen from unexpected BSSID {bssid} "
                       f"(expected {expected_bssid})")
            alerts.raise_alert("Possible rogue access point", detail)
            database.log_event(
                event_type="rogue_ap",
                ssid=ssid,
                bssid=bssid,
                detail=detail,
            )
