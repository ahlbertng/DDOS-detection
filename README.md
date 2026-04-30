# HNG Stage 3 — DDoS Anomaly Detection Engine

An anomaly detection daemon that watches all incoming HTTP traffic in real time, learns what normal looks like, and automatically responds when something deviates. Whether from a single aggressive IP or a global traffic spike.

---

> Dashboard refreshes every 3 seconds. Nextcloud is accessible via raw IP only as per task requirements.

---

## Blog Post

> https://ahlbert.hashnode.dev/how-i-built-a-real-time-ddos-detection-engine-from-scratch-no-fail2ban-allowed

---

## Language Choice

**Python**  chosen for its excellent standard library (`collections.deque`, `statistics`, `threading`), rapid iteration speed, and first-class support for the FastAPI dashboard. The daemon is fully concurrent using Python threads, one per subsystem which is well-suited for I/O-bound log monitoring and background detection loops.

---

## Architecture Overview

```
Nginx (JSON logs) → HNG-nginx-logs volume → LogMonitor
                                                  ↓
                                           BaselineEngine
                                                  ↓
                                          AnomalyDetector
                                           ↙         ↘
                                       Blocker    SlackNotifier
                                          ↓
                                      Unbanner (backoff)
                                          ↓
                                       Dashboard (FastAPI)
```

See `docs/architecture.png` for the full diagram.

---

## How the Sliding Window Works

Two `deque` based windows track request rates over the last **60 seconds**:

- `global_window`  one timestamp per request across all IPs
- `ip_windows[ip]`  one timestamp per request per source IP
- `ip_error_windows[ip]`  one timestamp per 4xx/5xx response per IP

**Eviction logic** runs on every log line processed:

```python
cutoff = now - 60  # 60-second window

# Global eviction
while global_window and global_window[0] < cutoff:
    global_window.popleft()

# Per-IP eviction
for ip, dq in ip_windows.items():
    while dq and dq[0] < cutoff:
        dq.popleft()
    if not dq:
        del ip_windows[ip]  # clean up idle IPs
```

Because deques are ordered by time (oldest on the left), eviction is O(1) per expired entry, no sorting, no scanning. The length of the deque at any moment equals the request count in the last 60 seconds.

---

## How the Baseline Works

The `BaselineEngine` computes a rolling baseline from a **30-minute window** of per-second request counts, recalculated every **60 seconds**.

**Window size:** 1800 seconds (`baseline_window_seconds: 1800` in config.yaml)

**Recalculation interval:** 60 seconds (`recalculation_interval_seconds: 60`)

**Per-hour slots:** Each second's count is also stored in `hourly_slots[HH]`  a deque keyed by the current UTC hour. When the current hour has accumulated at least `min_baseline_samples` (120) data points, the detector prefers the current hour's data over the global 30-minute window. This makes the baseline adapt to time-of-day traffic patterns.

**Floor values** prevent false positives during cold start or extremely quiet periods:
- `mean_floor: 1.0`  effective mean never drops below 1.0 req/s
- `stddev_floor: 0.5`  effective stddev never drops below 0.5

**Recalculation logic:**
```python
if len(current_hour_samples) >= min_samples:
    samples = current_hour_samples       # prefer current hour
else:
    samples = per_second_counts          # fall back to 30-min window

mean = max(statistics.mean(samples), mean_floor)
stddev = max(statistics.pstdev(samples), stddev_floor)
```

Every recalculation writes a structured entry to the audit log:
```
[timestamp] BASELINE - | recalculated | - | mean=1.2,std=0.6 | -
```

---

## Detection Logic

The `AnomalyDetector` evaluates every IP and the global rate on each cycle. An anomaly is flagged when **either** condition fires first:

1. **Z-score threshold:** `(rate - mean) / stddev > 3.0`
2. **Multiplier threshold:** `rate > mean * 5.0`

**Error surge tightening:** If an IP's 4xx/5xx rate exceeds `3x` the baseline error mean, its thresholds are automatically tightened:
- Z-score threshold drops from 3.0 → 2.0
- Multiplier drops from 5.0 → 3.0

All thresholds live in `config.yaml` — nothing is hardcoded:

```yaml
detection:
  zscore_threshold: 3.0
  multiplier_threshold: 5.0
  error_multiplier_threshold: 3.0
```

---

## How iptables Blocking Works

When an IP is flagged as anomalous, the `Blocker` inserts a DROP rule at the top of the INPUT chain:

```bash
iptables -I INPUT -s <ip> -j DROP
```

The `-I` flag inserts at position 1, ensuring the DROP fires before any ACCEPT rules. The detector container runs with `privileged: true` and `network_mode: host` so it has direct access to the host's iptables.

**Ban escalation schedule (per IP):**
| Strike | Duration |
|--------|----------|
| 1st | 10 minutes (600s) |
| 2nd | 30 minutes (1800s) |
| 3rd | 2 hours (7200s) |
| 4th+ | Permanent |

The `Unbanner` thread checks every 30 seconds for expired bans and removes the iptables rule:
```bash
iptables -D INPUT -s <ip> -j DROP
```

A Slack notification is sent on every ban and unban.

---

## Slack Alerts

All alerts include: condition fired, current rate, baseline mean/stddev, timestamp, and ban duration.

Store your webhook URL in `.env`:
```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Three alert types:
- **Ban alert** — fired when an IP is blocked
- **Unban alert** — fired when a ban expires
- **Global alert** — fired when global traffic spikes (no block, alert only)

---

## Live Dashboard

Served at `http://ahlbert.duckdns.org`, refreshes every 3 seconds. Shows:

- Banned IPs with condition, rate, duration, and time remaining
- Global requests/second
- Top 10 source IPs by request count
- CPU and memory usage
- Effective mean and stddev
- System uptime

---

## Repository Structure

```
detector/
  main.py          # Entry point — starts all threads
  monitor.py       # Tails nginx log, feeds sliding windows
  baseline.py      # Rolling 30-min baseline, hourly slots
  detector.py      # Z-score + multiplier anomaly detection
  blocker.py       # iptables banning with strike escalation
  unbanner.py      # Backoff unban scheduler
  notifier.py      # Slack webhook alerts
  dashboard.py     # FastAPI live metrics UI
  state.py         # Shared state dataclass (deques, locks)
  utils.py         # JSON parsing, IP extraction, audit logging
  config.yaml      # All thresholds and settings
  requirements.txt
nginx/
  nginx.conf       # Reverse proxy with JSON access logs
docs/
  architecture.png
screenshots/
  Tool-running.png
  Ban-slack.png
  Unban-slack.png
  Global-alert-slack.png
  Iptables-banned.png
  Audit-log.png
  Baseline-graph.png
README.md
docker-compose.yml
.env
```

---

## Setup — Fresh VPS to Fully Running Stack

### 1. Server Requirements
- Ubuntu 22.04 or 24.04
- Minimum 2 vCPU, 2 GB RAM
- Ports open: 22 (SSH), 80 (HTTP), 8080 (Dashboard)

### 2. Install Docker

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
newgrp docker
```

### 3. Clone the Repo

```bash
git clone https://github.com/ahlbertng/DDOS-detection.git
cd DDOS-detection
```

### 4. Configure Environment

```bash
# Create .env with your Slack webhook
echo "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL" > .env

# Create audit log file
touch detector/audit.log
```

### 5. Launch the Stack

```bash
docker compose up -d --build
```

### 6. Verify

```bash
# All 3 containers should show "Up"
docker compose ps

# Detector should show uvicorn running
docker logs hng-detector --follow

# Dashboard should return 200
curl -s -o /dev/null -w "%{http_code}" http://YOUR_DOMAIN_OR_IP

# Nginx JSON logs should be writing
docker exec hng-nginx tail -5 /var/log/nginx/hng-access.log
```

### 7. Test Detection

```bash
# Fire 300 concurrent requests to trigger anomaly detection
for i in $(seq 1 300); do
  curl -s http://YOUR_DOMAIN_OR_IP > /dev/null &
done
wait

# Check ban was applied
cat detector/audit.log | tail -10
sudo iptables -L INPUT -n --line-numbers
```

---

## Audit Log Format

Every ban, unban, and baseline recalculation is written to `/app/audit.log`:

```
[timestamp] ACTION ip | condition | rate | baseline | duration
```

Examples:
```
[2026-04-28T11:13:11.999264+00:00] BAN 18.205.189.110 | zscore>3.0 (322.0) | 162/60s | mean=1.0,std=0.5 | 600s
[2026-04-28T11:23:11.000000+00:00] UNBAN 18.205.189.110 | ban_expired | - | - | 600s
[2026-04-28T11:13:05.880093+00:00] BASELINE - | recalculated | - | mean=1.0,std=0.5 | -
```
