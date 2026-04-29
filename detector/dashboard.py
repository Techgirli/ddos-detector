import time
import threading
import logging
import psutil
from flask import Flask, jsonify, Response

logger = logging.getLogger("dashboard")

_START_TIME = time.time()


_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>HNG Anomaly Detection Engine</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #060a10;
    --panel: #0b1220;
    --border: #1a2d4a;
    --accent: #00d4ff;
    --accent2: #ff4560;
    --accent3: #00e396;
    --text: #c8d8e8;
    --muted: #4a6080;
    --warn: #ffa500;
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui: 'Exo 2', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    min-height: 100vh;
    padding: 0;
  }

  /* Scanline effect */
  body::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,212,255,0.015) 2px,
      rgba(0,212,255,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  header {
    background: linear-gradient(135deg, #060a10 0%, #0b1a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 18px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    font-family: var(--font-mono);
    font-size: 1.1rem;
    color: var(--accent);
    letter-spacing: 0.15em;
    text-transform: uppercase;
  }

  .logo span { color: var(--accent2); }

  .status-bar {
    display: flex;
    gap: 24px;
    align-items: center;
    font-family: var(--font-mono);
    font-size: 0.75rem;
  }

  .pulse {
    width: 8px; height: 8px;
    background: var(--accent3);
    border-radius: 50%;
    display: inline-block;
    animation: pulse 1.4s ease-in-out infinite;
    margin-right: 6px;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.7); }
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    padding: 24px 32px;
    max-width: 1600px;
    margin: 0 auto;
  }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s;
  }

  .panel:hover { border-color: var(--accent); }

  .panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent), transparent);
  }

  .panel-title {
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 12px;
    font-family: var(--font-mono);
  }

  .stat-big {
    font-size: 2.8rem;
    font-weight: 800;
    color: var(--accent);
    line-height: 1;
    font-family: var(--font-mono);
  }

  .stat-sub {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 6px;
    font-family: var(--font-mono);
  }

  .span-2 { grid-column: span 2; }
  .span-3 { grid-column: span 3; }
  .span-4 { grid-column: span 4; }

  /* Banned IPs table */
  table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-mono);
    font-size: 0.78rem;
  }

  th {
    text-align: left;
    color: var(--muted);
    font-size: 0.65rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 8px 8px;
    border-bottom: 1px solid rgba(26,45,74,0.5);
    vertical-align: middle;
  }

  tr:last-child td { border-bottom: none; }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 2px;
    font-size: 0.65rem;
    font-family: var(--font-mono);
    letter-spacing: 0.1em;
  }

  .badge-danger { background: rgba(255,69,96,0.2); color: var(--accent2); border: 1px solid var(--accent2); }
  .badge-perm { background: rgba(255,69,96,0.4); color: #ff8080; border: 1px solid #ff4040; }
  .badge-ok { background: rgba(0,227,150,0.1); color: var(--accent3); border: 1px solid var(--accent3); }

  /* Bar chart for top IPs */
  .ip-bar-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
    font-family: var(--font-mono);
    font-size: 0.75rem;
  }

  .ip-label { width: 130px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .ip-bar-wrap { flex: 1; background: rgba(26,45,74,0.6); border-radius: 2px; height: 10px; }
  .ip-bar { height: 10px; border-radius: 2px; background: linear-gradient(90deg, var(--accent), #0080aa); transition: width 0.5s; }
  .ip-count { width: 40px; text-align: right; color: var(--accent); }

  /* Baseline history mini chart */
  canvas { display: block; width: 100%; }

  /* Resource gauges */
  .gauge-wrap {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
  }
  .gauge-label { font-family: var(--font-mono); font-size: 0.75rem; width: 60px; }
  .gauge-bar-wrap { flex: 1; background: rgba(26,45,74,0.6); border-radius: 2px; height: 12px; }
  .gauge-bar { height: 12px; border-radius: 2px; transition: width 0.5s; }
  .gauge-value { font-family: var(--font-mono); font-size: 0.75rem; width: 40px; text-align: right; }

  .no-data { color: var(--muted); font-family: var(--font-mono); font-size: 0.8rem; padding: 12px 0; }

  /* Alert feed */
  .alert-item {
    padding: 8px 10px;
    border-left: 3px solid var(--accent2);
    margin-bottom: 6px;
    background: rgba(255,69,96,0.05);
    font-family: var(--font-mono);
    font-size: 0.72rem;
    line-height: 1.5;
  }

  .alert-time { color: var(--muted); font-size: 0.65rem; }

  @media (max-width: 1100px) {
    .grid { grid-template-columns: repeat(2, 1fr); }
    .span-3 { grid-column: span 2; }
    .span-4 { grid-column: span 2; }
  }
  @media (max-width: 700px) {
    .grid { grid-template-columns: 1fr; padding: 16px; }
    .span-2, .span-3, .span-4 { grid-column: span 1; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">HNG <span>//</span> Anomaly Detection Engine</div>
  <div class="status-bar">
    <span><span class="pulse"></span>LIVE</span>
    <span id="hdr-uptime">—</span>
    <span id="hdr-time">—</span>
  </div>
</header>

<div class="grid">

  <!-- Global req/s -->
  <div class="panel">
    <div class="panel-title">Global Req / 60s</div>
    <div class="stat-big" id="global-rate">—</div>
    <div class="stat-sub" id="global-sub">Baseline: —</div>
  </div>

  <!-- Banned IPs count -->
  <div class="panel">
    <div class="panel-title">Banned IPs</div>
    <div class="stat-big" id="banned-count" style="color:var(--accent2)">—</div>
    <div class="stat-sub">Currently blocked</div>
  </div>

  <!-- CPU -->
  <div class="panel">
    <div class="panel-title">CPU Usage</div>
    <div class="stat-big" id="cpu-val">—</div>
    <div class="stat-sub">%</div>
  </div>

  <!-- Memory -->
  <div class="panel">
    <div class="panel-title">Memory Usage</div>
    <div class="stat-big" id="mem-val">—</div>
    <div class="stat-sub" id="mem-sub">—</div>
  </div>

  <!-- Baseline stats -->
  <div class="panel span-2">
    <div class="panel-title">Effective Baseline</div>
    <div style="display:flex; gap:32px; margin-top:4px">
      <div>
        <div class="stat-big" id="b-mean" style="font-size:2rem">—</div>
        <div class="stat-sub">Mean req/s</div>
      </div>
      <div>
        <div class="stat-big" id="b-stddev" style="font-size:2rem; color:var(--accent3)">—</div>
        <div class="stat-sub">Std Dev</div>
      </div>
      <div>
        <div class="stat-big" id="b-errrate" style="font-size:2rem; color:var(--warn)">—</div>
        <div class="stat-sub">Error rate/s</div>
      </div>
    </div>
    <div class="stat-sub" style="margin-top:10px" id="b-source">Source: —</div>
  </div>

  <!-- Uptime -->
  <div class="panel span-2">
    <div class="panel-title">System Uptime</div>
    <div class="stat-big" id="uptime-val" style="font-size:1.8rem; color:var(--accent3)">—</div>
    <div class="stat-sub">Daemon running since start</div>
  </div>

  <!-- Banned IPs table -->
  <div class="panel span-2">
    <div class="panel-title">Banned IP List</div>
    <div id="banned-table-wrap">
      <div class="no-data">No IPs currently banned</div>
    </div>
  </div>

  <!-- Top 10 IPs -->
  <div class="panel span-2">
    <div class="panel-title">Top 10 Source IPs (last 60s)</div>
    <div id="top-ips-wrap">
      <div class="no-data">Collecting traffic data…</div>
    </div>
  </div>

  <!-- Resource gauges -->
  <div class="panel span-2">
    <div class="panel-title">Resource Gauges</div>
    <div class="gauge-wrap">
      <div class="gauge-label">CPU</div>
      <div class="gauge-bar-wrap"><div class="gauge-bar" id="g-cpu" style="background:linear-gradient(90deg,#00d4ff,#0080aa); width:0%"></div></div>
      <div class="gauge-value" id="g-cpu-v">0%</div>
    </div>
    <div class="gauge-wrap">
      <div class="gauge-label">Memory</div>
      <div class="gauge-bar-wrap"><div class="gauge-bar" id="g-mem" style="background:linear-gradient(90deg,#00e396,#009966); width:0%"></div></div>
      <div class="gauge-value" id="g-mem-v">0%</div>
    </div>
    <div class="gauge-wrap">
      <div class="gauge-label">Disk</div>
      <div class="gauge-bar-wrap"><div class="gauge-bar" id="g-disk" style="background:linear-gradient(90deg,#ffa500,#cc7a00); width:0%"></div></div>
      <div class="gauge-value" id="g-disk-v">0%</div>
    </div>
  </div>

  <!-- Baseline chart -->
  <div class="panel span-2">
    <div class="panel-title">Baseline Mean Over Time</div>
    <canvas id="baseline-chart" height="120"></canvas>
  </div>

</div>

<script>
const $ = id => document.getElementById(id);

function fmt(n, d=1) { return Number(n).toFixed(d); }

function uptimeStr(sec) {
  sec = Math.floor(sec);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

function renderBannedTable(bans) {
  const wrap = $('banned-table-wrap');
  if (!bans || bans.length === 0) {
    wrap.innerHTML = '<div class="no-data">No IPs currently banned</div>';
    return;
  }
  let html = `<table><thead><tr>
    <th>IP Address</th><th>Bans</th><th>Condition</th><th>Rate</th><th>Remaining</th>
  </tr></thead><tbody>`;
  bans.forEach(b => {
    const cls = b.remaining === 'permanent' ? 'badge-perm' : 'badge-danger';
    html += `<tr>
      <td><code style="color:var(--accent2)">${b.ip}</code></td>
      <td>${b.ban_count}</td>
      <td style="color:var(--muted);font-size:0.7rem">${b.condition || '-'}</td>
      <td>${fmt(b.rate)}</td>
      <td><span class="badge ${cls}">${b.remaining}</span></td>
    </tr>`;
  });
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function renderTopIPs(ips) {
  const wrap = $('top-ips-wrap');
  if (!ips || ips.length === 0) {
    wrap.innerHTML = '<div class="no-data">No traffic data yet</div>';
    return;
  }
  const max = ips[0][1] || 1;
  let html = '';
  ips.forEach(([ip, count]) => {
    const pct = Math.round((count / max) * 100);
    html += `<div class="ip-bar-row">
      <div class="ip-label">${ip}</div>
      <div class="ip-bar-wrap"><div class="ip-bar" style="width:${pct}%"></div></div>
      <div class="ip-count">${count}</div>
    </div>`;
  });
  wrap.innerHTML = html;
}

// Mini line chart
const chartHistory = [];
function renderChart(history) {
  if (history) history.forEach(p => chartHistory.push(p));
  const canvas = $('baseline-chart');
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 400;
  const H = 120;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);

  const points = chartHistory.slice(-60);
  if (points.length < 2) return;

  const means = points.map(p => p[1]);
  const minV = Math.min(...means) * 0.8;
  const maxV = Math.max(...means) * 1.2 || 1;

  const toY = v => H - 10 - ((v - minV) / (maxV - minV)) * (H - 20);
  const toX = i => (i / (points.length - 1)) * W;

  // Grid lines
  ctx.strokeStyle = 'rgba(26,45,74,0.8)';
  ctx.lineWidth = 1;
  [0.25, 0.5, 0.75].forEach(f => {
    const y = H * f;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  });

  // Mean line
  ctx.beginPath();
  ctx.strokeStyle = '#00d4ff';
  ctx.lineWidth = 2;
  points.forEach((p, i) => {
    i === 0 ? ctx.moveTo(toX(i), toY(p[1])) : ctx.lineTo(toX(i), toY(p[1]));
  });
  ctx.stroke();

  // Stddev band
  ctx.beginPath();
  points.forEach((p, i) => ctx.lineTo(toX(i), toY(p[1] + p[2])));
  [...points].reverse().forEach((p, i) => ctx.lineTo(toX(points.length - 1 - i), toY(Math.max(0, p[1] - p[2]))));
  ctx.closePath();
  ctx.fillStyle = 'rgba(0,212,255,0.08)';
  ctx.fill();
}

async function refresh() {
  try {
    const r = await fetch('/metrics');
    const d = await r.json();

    // Header
    $('hdr-uptime').textContent = uptimeStr(d.uptime_seconds);
    $('hdr-time').textContent = new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';

    // Stats
    $('global-rate').textContent = d.global_rate;
    $('global-sub').textContent = `Baseline: mean=${fmt(d.baseline.mean)} ±${fmt(d.baseline.stddev)}`;
    $('banned-count').textContent = d.banned_count;
    $('cpu-val').textContent = fmt(d.cpu_percent, 0);
    $('mem-val').textContent = fmt(d.memory.percent, 0);
    $('mem-sub').textContent = `${d.memory.used_mb} MB / ${d.memory.total_mb} MB`;
    $('b-mean').textContent = fmt(d.baseline.mean);
    $('b-stddev').textContent = fmt(d.baseline.stddev);
    $('b-errrate').textContent = fmt(d.baseline.error_mean);
    $('b-source').textContent = 'Source: ' + (d.baseline.source || '—');
    $('uptime-val').textContent = uptimeStr(d.uptime_seconds);

    // Gauges
    $('g-cpu').style.width = Math.min(d.cpu_percent, 100) + '%';
    $('g-cpu-v').textContent = fmt(d.cpu_percent, 0) + '%';
    $('g-mem').style.width = Math.min(d.memory.percent, 100) + '%';
    $('g-mem-v').textContent = fmt(d.memory.percent, 0) + '%';
    $('g-disk').style.width = Math.min(d.disk.percent, 100) + '%';
    $('g-disk-v').textContent = fmt(d.disk.percent, 0) + '%';

    renderBannedTable(d.banned_ips);
    renderTopIPs(d.top_ips);
    renderChart(d.baseline_history);
  } catch(e) {
    console.warn('Metrics fetch failed:', e);
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class Dashboard:
    """
    Flask-based dashboard server.

    Parameters
    ----------
    host, port      : Bind address.
    detector        : AnomalyDetector (for rates, top IPs).
    baseline        : BaselineEngine  (for mean, stddev).
    unbanner        : AutoUnbanner    (for banned IP list).
    """

    def __init__(self, host: str, port: int, detector, baseline, unbanner):
        self.host = host
        self.port = port
        self.detector = detector
        self.baseline = baseline
        self.unbanner = unbanner
        self._app = Flask(__name__)
        self._last_history_idx = 0
        self._setup_routes()

    def _setup_routes(self):
        app = self._app

        @app.route("/")
        def index():
            return Response(_HTML, mimetype="text/html")

        @app.route("/metrics")
        def metrics():
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            uptime = time.time() - _START_TIME

            banned = self.unbanner.get_records()

            # Incremental baseline history
            full_history = self.baseline.history
            new_points = full_history[self._last_history_idx:]
            self._last_history_idx = len(full_history)

            data = {
                "uptime_seconds": round(uptime),
                "global_rate": self.detector.global_rate,
                "banned_count": len(banned),
                "banned_ips": banned,
                "top_ips": self.detector.get_top_ips(10),
                "cpu_percent": cpu,
                "memory": {
                    "percent": mem.percent,
                    "used_mb": round(mem.used / 1024 / 1024),
                    "total_mb": round(mem.total / 1024 / 1024),
                },
                "disk": {
                    "percent": disk.percent,
                },
                "baseline": {
                    "mean": round(self.baseline.mean, 2),
                    "stddev": round(self.baseline.stddev, 2),
                    "error_mean": round(self.baseline.error_mean, 4),
                    "source": self.baseline.effective_source,
                },
                "baseline_history": [
                    [p[0], round(p[1], 2), round(p[2], 2)] for p in new_points
                ],
            }
            return jsonify(data)

        @app.route("/health")
        def health():
            return jsonify({"status": "ok", "uptime": round(time.time() - _START_TIME)})

    def start(self):
        """Start Flask in a daemon thread."""
        t = threading.Thread(
            target=self._app.run,
            kwargs={
                "host": self.host,
                "port": self.port,
                "debug": False,
                "use_reloader": False,
            },
            daemon=True,
            name="Dashboard",
        )
        t.start()
        logger.info("Dashboard started at http://%s:%d", self.host, self.port)
