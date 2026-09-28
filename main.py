#!/usr/bin/env python3
"""
main.py — NetworkEye entry point.

NetworkEye is a passive Wireless Intrusion Detection System (WIDS).
It listens to WiFi traffic already in the air and flags three attack
signatures, without ever transmitting a single packet itself:

  1. Deauthentication bursts  (Detectors/deauth_detector.py)
  2. Rogue access points      (Detectors/rogue_ap_detector.py)
  3. Evil twin access points  (Detectors/evil_twin_detector.py)

Setup before running:
    pip install scapy plyer
    sudo airmon-ng start wlan0      # creates e.g. wlan0mon
    # edit configs.py: set INTERFACE and (optionally) TRUSTED_NETWORKS

Usage:
    sudo python3 main.py
"""

import sys

import configs
from sniffer import Sniffer
from Detectors.deauth_detector import DeauthDetector
from Detectors.rogue_ap_detector import RogueAPDetector
from Detectors.evil_twin_detector import EvilTwinDetector


def main():
    deauth_detector = DeauthDetector()
    rogue_ap_detector = RogueAPDetector()
    evil_twin_detector = EvilTwinDetector()

    sniffer = Sniffer(
        interface=configs.INTERFACE,
        deauth_detector=deauth_detector,
        rogue_ap_detector=rogue_ap_detector,
        evil_twin_detector=evil_twin_detector,
    )

    try:
        sniffer.start()
    except PermissionError:
        print("Permission denied — raw packet capture needs root. "
              "Try: sudo python3 main.py")
        sys.exit(1)
    except OSError as e:
        print(f"Could not open interface '{configs.INTERFACE}': {e}")
        print("Is it in monitor mode? Check with: iwconfig")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nNetworkEye stopped.")


if __name__ == "__main__":
    main()
