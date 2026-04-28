import json
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def safe_json(line):
    try:
        return json.loads(line)
    except Exception:
        return None


def extract_client_ip(record):
    xff = record.get("source_ip") or ""
    remote = record.get("remote_addr") or ""

    if xff and xff != "-":
        return xff.split(",")[0].strip()

    return remote.strip() or "unknown"


def audit(config, action, ip="-", condition="-", rate="-", baseline="-", duration="-"):
    path = config.get("audit_log", "/app/audit.log")
    line = f"[{now_iso()}] {action} {ip} | {condition} | {rate} | {baseline} | {duration}\n"

    with open(path, "a", encoding="utf-8") as f:
        f.write(line)