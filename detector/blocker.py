import subprocess
import time
from utils import audit


class Blocker:
    def __init__(self, config, state, notifier):
        self.config = config
        self.state = state
        self.notifier = notifier

    def _run(self, cmd):
        try:
            subprocess.run(cmd, check=False, capture_output=True, text=True)
        except Exception:
            pass

    def _rule_exists(self, ip):
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0

    def ban(self, ip, condition, rate, baseline):
        if ip in ("unknown", "127.0.0.1", "::1"):
            return

        with self.state.lock:
            if ip in self.state.banned_ips:
                return

            self.state.ban_strikes[ip] += 1
            strike = self.state.ban_strikes[ip]

            ban_cfg = self.config.get("ban", {})
            durations = ban_cfg.get("durations_seconds", [600, 1800, 7200])
            permanent_after = ban_cfg.get("permanent_after", 4)

            if strike >= permanent_after:
                duration = None
                duration_text = "permanent"
                expires_at = None
            else:
                duration = durations[min(strike - 1, len(durations) - 1)]
                duration_text = f"{duration}s"
                expires_at = time.time() + duration

            self.state.banned_ips[ip] = {
                "condition": condition,
                "rate": rate,
                "baseline": baseline,
                "duration": duration_text,
                "expires_at": expires_at,
                "strike": strike,
                "banned_at": time.time(),
            }
        
        if not self._rule_exists(ip):
            self._run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])

        audit(self.config, "BAN", ip, condition, rate, baseline, duration_text)
        self.notifier.ban_alert(ip, condition, rate, baseline, duration_text)

    def unban(self, ip):
        with self.state.lock:
            info = self.state.banned_ips.get(ip)
            if not info:
                return

            duration = info.get("duration", "-")
            del self.state.banned_ips[ip]

        self._run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        audit(self.config, "UNBAN", ip, "ban_expired", "-", "-", duration)
        self.notifier.unban_alert(ip, duration)