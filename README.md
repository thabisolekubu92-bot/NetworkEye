# NetworkEye
Network eye for capturing unusual wireless activities like evil twin networks/unauthorised deauthentications 
# NetworkEye — Passive Wireless Intrusion Detection System

NetworkEye listens to WiFi traffic already in the air and flags signs
of common wireless attacks — without ever transmitting, injecting, or
sending a single packet of its own. Because it's purely passive, it's
safe to run continuously on your own network as a monitoring tool.

## What it detects

| Detector | File | What it flags |
|---|---|---|
| Deauth burst | `Detectors/deauth_detector.py` | An abnormal spike of deauthentication frames aimed at one access point — the signature of an active deauth attack, often used to force a handshake capture or as denial-of-service |
| Rogue AP | `Detectors/rogue_ap_detector.py` | One of *your* registered SSIDs suddenly broadcasting from a MAC address (BSSID) you didn't register — a sign someone is impersonating your network |
| Evil twin | `Detectors/evil_twin_detector.py` | Any SSID being broadcast simultaneously by more than one BSSID — a general-purpose fingerprint of duplicated/spoofed access points |

## Architecture

```
main.py               entry point — wires everything together
configs.py             all settings live here (interface, thresholds, trusted networks)
sniffer.py             the ONLY file that touches raw packets (passive sniff only)
database.py            SQLite logging of every detected event
alerts.py              console + optional desktop notification output
Detectors/
    deauth_detector.py
    rogue_ap_detector.py
    evil_twin_detector.py
```

Each detector is independent and only knows how to answer one question
("is this a burst?", "is this BSSID unexpected?"). `sniffer.py` is the
only place raw 802.11 frames are parsed, and it just routes clean,
already-extracted data (ssid, bssid, reason code, etc.) to whichever
detector cares about it. This separation is what makes it easy to add
a fourth or fifth detector later without touching existing code.

## Setup

```bash
# 1. Install dependencies
pip install scapy plyer

# 2. Put your wireless adapter into monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0        # creates e.g. wlan0mon

# 3. Edit configs.py
#    - set INTERFACE to match your monitor-mode interface name
#    - (optional) add your own network to TRUSTED_NETWORKS to enable
#      rogue AP detection, e.g.:
#      TRUSTED_NETWORKS = {"MyHomeWiFi": "AA:BB:CC:DD:EE:FF"}

# 4. Run it
sudo python3 main.py
```

## Example output

```
NetworkEye listening on wlan0mon... (Ctrl+C to stop)

*** ALERT: Possible deauth attack ***
    BSSID AA:BB:CC:DD:EE:FF — 10 deauth frames in 10s (latest: AA:BB:CC:DD:EE:FF -> 11:22:33:44:55:66, reason=7)

*** ALERT: Possible evil twin access point ***
    SSID 'FreeAirportWiFi' is being broadcast by multiple BSSIDs: 22:22:22:22:22:22, 33:33:33:33:33:33
```

All events are also written to `networkeye.db` (SQLite) for later
review — query it directly or extend `database.py` with a small
reporting script.

## Roadmap

- [ ] Flask dashboard for live viewing of `networkeye.db` events
- [ ] Email/Telegram alert channel (alongside desktop notifications)
- [ ] Signal-strength anomaly detection
- [ ] Probe-request tracking (detect devices being lured to malicious APs)

## Legal note

NetworkEye is passive-only — it captures frames already being
broadcast over the air on the channel your adapter listens to, and
never sends deauth, injection, or handshake-capture packets itself.
Built for monitoring networks you own or are authorized to monitor.
