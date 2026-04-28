import threading
import time
import yaml
import uvicorn

from state import SharedState
from monitor import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector
from notifier import SlackNotifier
from blocker import Blocker
from unbanner import Unbanner
from dashboard import create_dashboard


def load_config():
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def per_second_baseline_loop(state, baseline):
    last_total = 0

    while True:
        with state.lock:
            current_total = len(state.global_window)

        count_this_second = max(current_total - last_total, 0)
        last_total = current_total

        baseline.add_second_count(count_this_second)
        baseline.recalculate_if_due()

        time.sleep(1)


def detector_loop(detector):
    while True:
        detector.evaluate()
        time.sleep(1)


def main():
    config = load_config()
    state = SharedState()

    notifier = SlackNotifier(config)
    blocker = Blocker(config, state, notifier)
    baseline = BaselineEngine(config, state)
    detector = AnomalyDetector(config, state, blocker, notifier)
    monitor = LogMonitor(config, state)
    unbanner = Unbanner(state, blocker)

    threading.Thread(target=monitor.run, daemon=True).start()
    threading.Thread(target=per_second_baseline_loop, args=(state, baseline), daemon=True).start()
    threading.Thread(target=detector_loop, args=(detector,), daemon=True).start()
    threading.Thread(target=unbanner.run, daemon=True).start()

    app = create_dashboard(state)

    dash_cfg = config.get("dashboard", {})
    uvicorn.run(
        app,
        host=dash_cfg.get("host", "0.0.0.0"),
        port=int(dash_cfg.get("port", 8080))
    )


if __name__ == "__main__":
    main()