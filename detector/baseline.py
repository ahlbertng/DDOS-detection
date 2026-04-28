import statistics
import time
from datetime import datetime
from utils import audit


class BaselineEngine:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self.det_cfg = config.get("detection", {})

    def add_second_count(self, count):
        now = time.time()
        hour_key = datetime.utcnow().strftime("%H")

        with self.state.lock:
            self.state.per_second_counts.append((now, count))
            self.state.hourly_slots[hour_key].append(count)

            cutoff = now - self.det_cfg.get("baseline_window_seconds", 1800)

            while self.state.per_second_counts and self.state.per_second_counts[0][0] < cutoff:
                self.state.per_second_counts.popleft()

    def recalculate_if_due(self):
        now = time.time()
        interval = self.det_cfg.get("recalculation_interval_seconds", 60)

        with self.state.lock:
            if now - self.state.last_baseline_recalc < interval:
                return

            self.state.last_baseline_recalc = now

            min_samples = self.det_cfg.get("min_baseline_samples", 120)
            mean_floor = self.det_cfg.get("mean_floor", 1.0)
            std_floor = self.det_cfg.get("stddev_floor", 0.5)

            hour_key = datetime.utcnow().strftime("%H")
            current_hour_samples = list(self.state.hourly_slots[hour_key])

            if len(current_hour_samples) >= min_samples:
                samples = current_hour_samples
            else:
                samples = [count for _, count in self.state.per_second_counts]

            if len(samples) < 2:
                mean = mean_floor
                stddev = std_floor
            else:
                mean = max(statistics.mean(samples), mean_floor)
                stddev = max(statistics.pstdev(samples), std_floor)

            self.state.effective_mean = round(mean, 3)
            self.state.effective_stddev = round(stddev, 3)

            error_samples = []
            for dq in self.state.ip_error_windows.values():
                error_samples.append(len(dq))

            if error_samples:
                self.state.effective_error_mean = max(statistics.mean(error_samples), 1.0)
            else:
                self.state.effective_error_mean = 1.0

            audit(
                self.config,
                "BASELINE",
                "-",
                "recalculated",
                "-",
                f"mean={self.state.effective_mean},std={self.state.effective_stddev}",
                "-"
            )