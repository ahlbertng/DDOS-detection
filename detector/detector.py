class AnomalyDetector:
    def __init__(self, config, state, blocker, notifier):
        self.config = config
        self.state = state
        self.blocker = blocker
        self.notifier = notifier
        self.det_cfg = config.get("detection", {})
        self.global_alert_active = False

    def _condition(self, current_rate, mean, stddev, tightened=False):
        z_threshold = self.det_cfg.get("zscore_threshold", 3.0)
        multiplier = self.det_cfg.get("multiplier_threshold", 5.0)

        if tightened:
            z_threshold = max(2.0, z_threshold - 1.0)
            multiplier = max(3.0, multiplier - 2.0)

        zscore = (current_rate - mean) / stddev if stddev > 0 else 0

        if zscore > z_threshold:
            return True, f"zscore>{z_threshold} ({round(zscore, 2)})"

        if current_rate > mean * multiplier:
            return True, f"rate>{multiplier}x_mean"

        return False, "normal"

    def evaluate(self):
        with self.state.lock:
            mean = self.state.effective_mean
            stddev = self.state.effective_stddev
            global_rate = len(self.state.global_window)
            self.state.global_rate = global_rate

            ip_rates = {
                ip: len(window)
                for ip, window in self.state.ip_windows.items()
            }

            error_rates = {
                ip: len(window)
                for ip, window in self.state.ip_error_windows.items()
            }

            error_mean = self.state.effective_error_mean

        is_global_bad, global_condition = self._condition(global_rate, mean, stddev)

        if is_global_bad and not self.global_alert_active:
            self.notifier.global_alert(
                global_condition,
                f"{global_rate}/60s",
                f"mean={mean},std={stddev}"
            )
            self.global_alert_active = True

        if not is_global_bad:
            self.global_alert_active = False

        for ip, rate in ip_rates.items():
            error_rate = error_rates.get(ip, 0)
            error_multiplier = self.det_cfg.get("error_multiplier_threshold", 3.0)
            tightened = error_rate > error_mean * error_multiplier

            is_bad, condition = self._condition(rate, mean, stddev, tightened=tightened)

            if tightened:
                condition = f"{condition}; error_surge={error_rate}"

            if is_bad:
                self.blocker.ban(
                    ip,
                    condition,
                    f"{rate}/60s",
                    f"mean={mean},std={stddev}"
                )