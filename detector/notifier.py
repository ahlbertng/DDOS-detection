import requests
from utils import now_iso


class SlackNotifier:
    def __init__(self, config):
        self.webhook_url = (
            config.get("slack", {}).get("webhook_url")
            or ""
        )

    def send(self, title, fields):
        if not self.webhook_url or "YOUR_SLACK_WEBHOOK_URL" in self.webhook_url:
            return

        text_lines = [f"*{title}*"]
        for key, value in fields.items():
            text_lines.append(f"*{key}:* {value}")

        payload = {
            "text": "\n".join(text_lines)
        }

        try:
            requests.post(self.webhook_url, json=payload, timeout=4)
        except Exception:
            pass

    def ban_alert(self, ip, condition, rate, baseline, duration):
        self.send("🚨 HNG Detector: IP Banned", {
            "IP": ip,
            "Condition": condition,
            "Current rate": rate,
            "Baseline": baseline,
            "Timestamp": now_iso(),
            "Ban duration": duration,
        })

    def unban_alert(self, ip, duration):
        self.send("✅ HNG Detector: IP Unbanned", {
            "IP": ip,
            "Timestamp": now_iso(),
            "Previous ban duration": duration,
        })

    def global_alert(self, condition, rate, baseline):
        self.send("⚠️ HNG Detector: Global Anomaly", {
            "Condition": condition,
            "Current global rate": rate,
            "Baseline": baseline,
            "Timestamp": now_iso(),
            "Action": "Slack alert only",
        })