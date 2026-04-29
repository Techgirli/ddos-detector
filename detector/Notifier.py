import os
import time
import threading
import logging
import requests

logger = logging.getLogger("notifier")

COLOR_DANGER = "#FF3B30"
COLOR_WARNING = "#FF9500"
COLOR_GOOD = "#34C759"


class SlackNotifier:

    def __init__(self, webhook_url: str = None, timeout: int = 8):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.timeout = int(os.getenv("SLACK_TIMEOUT", timeout))
        self._lock = threading.Lock()

    def ban_alert(
        self,
        ip: str,
        rate: float,
        mean: float,
        stddev: float,
        condition: str,
        duration_seconds: int,
        error_surge: bool = False,
    ):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        duration_str = "permanent" if duration_seconds == - \
            1 else f"{duration_seconds}s"
        surge_tag = " *(error surge mode)*" if error_surge else ""

        text = (
            f":rotating_light: *IP BAN TRIGGERED*{surge_tag}\n"
            f">*IP:* `{ip}`\n"
            f">*Condition:* `{condition}`\n"
            f">*Current rate:* {rate:.1f} req/60s\n"
            f">*Baseline:* mean={mean:.2f} stddev={stddev:.2f}\n"
            f">*Ban duration:* {duration_str}\n"
            f">*Timestamp:* {ts}"
        )
        self._send(text, color=COLOR_DANGER)

    def unban_alert(
        self,
        ip: str,
        ban_count: int,
        duration_was: int,
        next_duration: int,
        condition: str,
    ):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        next_str = "permanent" if next_duration == -1 else f"{next_duration}s"
        text = (
            f":unlock: *IP UNBANNED*\n"
            f">*IP:* `{ip}`\n"
            f">*Ban #{ban_count}* lasted {duration_was}s\n"
            f">*Original condition:* {condition}\n"
            f">*Next ban if re-triggered:* {next_str}\n"
            f">*Timestamp:* {ts}"
        )
        self._send(text, color=COLOR_GOOD)

    def global_alert(
        self,
        rate: float,
        mean: float,
        stddev: float,
        condition: str,
    ):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f">*Condition:* `{condition}`\n"
            f">*Global rate:* {rate:.1f} req/60s\n"
            f">*Baseline:* mean={mean:.2f} stddev={stddev:.2f}\n"
            f">*Action:* Alert only (no IP to block)\n"
            f">*Timestamp:* {ts}"
        )
        self._send(text, color=COLOR_WARNING)

    def send_raw(self, message: str):
        """Send a pre-formatted string directly."""
        self._send(message)

    def _send(self, text: str, color: str = COLOR_WARNING):
        if not self.webhook_url or self.webhook_url == "YOUR_SLACK_WEBHOOK_URL_HERE":
            logger.warning("Slack webhook not configured — skipping alert")
            return

        payload = {
            "attachments": [
                {
                    "color": color,
                    "text": text,
                    "mrkdwn_in": ["text"],
                }
            ]
        }

        try:
            with self._lock:
                resp = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=self.timeout,
                )
            if resp.status_code != 200:
                logger.error(
                    "Slack webhook returned %d: %s", resp.status_code, resp.text[:200]
                )
            else:
                logger.debug("Slack alert sent successfully")
        except requests.RequestException as exc:
            logger.error("Failed to send Slack alert: %s", exc)
        except Exception as exc:
            logger.error("Unexpected error sending Slack alert: %s", exc)
