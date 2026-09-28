"""
configs.py — Central configuration for NetworkEye.

Keeping all tunable values in one file means you never have to hunt
through detector logic just to change a threshold or add a trusted
network. Edit this file to match your own setup before running main.py.
"""

# The monitor-mode interface NetworkEye listens on.
# Set this AFTER running: sudo airmon-ng start wlan0
INTERFACE = "wlan0mon"

# --- Deauth burst detector ---
DEAUTH_THRESHOLD = 10          # how many deauth frames...
DEAUTH_WINDOW_SECONDS = 10     # ...within this many seconds triggers an alert

# --- Rogue AP / Evil twin detector ---
# List your OWN trusted networks here as {ssid: bssid} pairs.
# If NetworkEye ever sees your SSID broadcast from a DIFFERENT bssid,
# that's a strong sign of a rogue AP or evil twin impersonating you.
#
# Find your router's real BSSID (MAC address) from its admin page,
# or by running airodump-ng once on your own network and noting the
# BSSID column next to your SSID.
TRUSTED_NETWORKS = {
    # "MyHomeWiFi": "AA:BB:CC:DD:EE:FF",
}

# --- Database ---
DATABASE_PATH = "networkeye.db"

# --- Alerts ---
ENABLE_DESKTOP_NOTIFICATIONS = True
