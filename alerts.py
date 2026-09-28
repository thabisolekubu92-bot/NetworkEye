"""
alerts.py — Turns a detected event into something a human actually notices.

Right now this supports:
  - Console output (always on, zero dependencies)
  - Desktop notifications (optional, needs the `plyer` package)

This is deliberately kept separate from the detectors themselves —
detectors decide *what* counts as suspicious, alerts.py just decides
*how to tell you*. That separation means you can swap in email/Telegram/
Slack alerting later without touching any detection logic.
"""

import configs

try:
    from plyer import notification
    _PLYER_AVAILABLE = True
except ImportError:
    _PLYER_AVAILABLE = False


def raise_alert(title, message):
    """Show an alert both in the console and, if enabled, as a desktop popup."""
    print(f"\n*** ALERT: {title} ***")
    print(f"    {message}\n")

    if configs.ENABLE_DESKTOP_NOTIFICATIONS:
        if _PLYER_AVAILABLE:
            try:
                notification.notify(
                    title=f"NetworkEye: {title}",
                    message=message,
                    timeout=10,
                )
            except Exception as e:
                # Desktop notifications can fail on headless/SSH setups —
                # never let that crash the actual monitoring.
                print(f"    (desktop notification failed: {e})")
        else:
            print("    (install `plyer` for desktop popups: pip install plyer)")
