"""
sniffer.py — The single point where NetworkEye touches raw traffic.

This is purely passive: it only calls scapy.sniff(), which listens to
frames already flying through the air on the channel your adapter is
tuned to. It never transmits, injects, or sends anything.

Two frame types matter to us:
  - Dot11Deauth  -> fed to the deauth burst detector
  - Dot11Beacon  -> tells us "SSID X is being broadcast by BSSID Y",
                    fed to both the rogue AP and evil twin detectors
"""

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt


class Sniffer:
    def __init__(self, interface, deauth_detector, rogue_ap_detector, evil_twin_detector):
        self.interface = interface
        self.deauth_detector = deauth_detector
        self.rogue_ap_detector = rogue_ap_detector
        self.evil_twin_detector = evil_twin_detector

    def start(self):
        print(f"NetworkEye listening on {self.interface}... (Ctrl+C to stop)\n")
        sniff(iface=self.interface, prn=self._handle_packet, store=0)

    def _handle_packet(self, pkt):
        if pkt.haslayer(Dot11Deauth):
            self._handle_deauth(pkt)
        elif pkt.haslayer(Dot11Beacon):
            self._handle_beacon(pkt)

    def _handle_deauth(self, pkt):
        dot11 = pkt[Dot11]
        bssid = dot11.addr3
        source = dot11.addr2
        target = dot11.addr1
        reason = pkt[Dot11Deauth].reason
        self.deauth_detector.handle(bssid=bssid, source=source,
                                     target=target, reason=reason)

    def _handle_beacon(self, pkt):
        bssid = pkt[Dot11].addr3
        # The SSID lives inside a Dot11Elt (information element) tagged as ID 0.
        ssid_elt = pkt.getlayer(Dot11Elt)
        try:
            ssid = ssid_elt.info.decode(errors="ignore") if ssid_elt else ""
        except Exception:
            ssid = ""

        if not ssid:
            return  # hidden/blank SSID beacon, nothing to compare

        self.rogue_ap_detector.handle(ssid=ssid, bssid=bssid)
        self.evil_twin_detector.handle(ssid=ssid, bssid=bssid)
