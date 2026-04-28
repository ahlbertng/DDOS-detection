import os
import time
from utils import safe_json, extract_client_ip


class LogMonitor:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self.log_path = config.get("log_path", "/var/log/nginx/hng-access.log")
        self.window_seconds = config.get("detection", {}).get("window_seconds", 60)

    def _evict_old(self, now):
        cutoff = now - self.window_seconds

        while self.state.global_window and self.state.global_window[0] < cutoff:
            self.state.global_window.popleft()

        for ip, dq in list(self.state.ip_windows.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self.state.ip_windows[ip]

        for ip, dq in list(self.state.ip_error_windows.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self.state.ip_error_windows[ip]

    def _process_record(self, record):
        now = time.time()
        ip = extract_client_ip(record)

        try:
            status = int(record.get("status", 0))
        except Exception:
            status = 0

        with self.state.lock:
            self.state.global_window.append(now)
            self.state.ip_windows[ip].append(now)
            self.state.top_ips[ip] += 1

            if status >= 400:
                self.state.ip_error_windows[ip].append(now)

            self.state.last_seen_log_line = str(record)

            self._evict_old(now)

    def run(self):
        while not os.path.exists(self.log_path):
            time.sleep(1)

        with open(self.log_path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.2)
                    continue

                record = safe_json(line.strip())
                if record:
                    self._process_record(record)