from collections import defaultdict, deque
from dataclasses import dataclass, field
import time
import threading


@dataclass
class SharedState:
    started_at: float = field(default_factory=time.time)

    global_window: deque = field(default_factory=deque)
    ip_windows: dict = field(default_factory=lambda: defaultdict(deque))
    ip_error_windows: dict = field(default_factory=lambda: defaultdict(deque))

    per_second_counts: deque = field(default_factory=deque)
    hourly_slots: dict = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=1800)))

    effective_mean: float = 1.0
    effective_stddev: float = 0.5
    effective_error_mean: float = 1.0

    banned_ips: dict = field(default_factory=dict)
    ban_strikes: dict = field(default_factory=lambda: defaultdict(int))
    top_ips: dict = field(default_factory=lambda: defaultdict(int))

    global_rate: int = 0
    last_baseline_recalc: float = 0.0
    last_seen_log_line: str = ""

    lock: threading.RLock = field(default_factory=threading.RLock)