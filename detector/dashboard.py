import time
import psutil
from typing import Any, Mapping, Protocol
from fastapi import FastAPI
from fastapi.responses import HTMLResponse


class DashboardState(Protocol):
    lock: Any
    started_at: float
    banned_ips: Mapping[str, Mapping[str, Any]]
    global_rate: int
    effective_mean: float
    effective_stddev: float
    top_ips: Mapping[str, int]
    last_seen_log_line: str


def create_dashboard(state: DashboardState) -> FastAPI:
    app: FastAPI = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        with state.lock:
            uptime = int(time.time() - state.started_at)
            banned_ips = dict(state.banned_ips)
            global_rate = state.global_rate
            mean = state.effective_mean
            stddev = state.effective_stddev
            top_ips = sorted(
                state.top_ips.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            last_line = state.last_seen_log_line

        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory().percent

        banned_rows = "".join(
            f"<tr><td>{ip}</td><td>{info['condition']}</td><td>{info['duration']}</td><td>{info['strike']}</td></tr>"
            for ip, info in banned_ips.items()
        ) or "<tr><td colspan='4'>No banned IPs</td></tr>"

        top_rows = "".join(
            f"<tr><td>{ip}</td><td>{count}</td></tr>"
            for ip, count in top_ips
        ) or "<tr><td colspan='2'>No traffic yet</td></tr>"

        return f"""
        <html>
        <head>
            <title>HNG Anomaly Detector</title>
            <meta http-equiv="refresh" content="3">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 30px; background: #0f172a; color: #e5e7eb; }}
                h1 {{ color: #38bdf8; }}
                .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }}
                .card {{ background: #111827; padding: 18px; border-radius: 12px; border: 1px solid #334155; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ border-bottom: 1px solid #334155; padding: 8px; text-align: left; }}
                code {{ color: #86efac; word-break: break-word; }}
            </style>
        </head>
        <body>
            <h1>HNG DDoS / Anomaly Detection Dashboard</h1>

            <div class="grid">
                <div class="card"><h3>Global Requests</h3><p>{global_rate}/60s</p></div>
                <div class="card"><h3>CPU</h3><p>{cpu}%</p></div>
                <div class="card"><h3>Memory</h3><p>{memory}%</p></div>
                <div class="card"><h3>Effective Mean</h3><p>{mean}</p></div>
                <div class="card"><h3>Effective Stddev</h3><p>{stddev}</p></div>
                <div class="card"><h3>Uptime</h3><p>{uptime}s</p></div>
            </div>

            <div class="card">
                <h2>Banned IPs</h2>
                <table>
                    <tr><th>IP</th><th>Condition</th><th>Duration</th><th>Strike</th></tr>
                    {banned_rows}
                </table>
            </div>

            <div class="card">
                <h2>Top 10 Source IPs</h2>
                <table>
                    <tr><th>IP</th><th>Total Requests Seen</th></tr>
                    {top_rows}
                </table>
            </div>

            <div class="card">
                <h2>Last Parsed Log Line</h2>
                <code>{last_line}</code>
            </div>
        </body>
        </html>
        """

    return app