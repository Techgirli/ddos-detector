# HNG Anomaly Detection Engine

> A real-time DDoS detection and automated response system built alongside Nextcloud, using sliding-window statistics and adaptive baselines.

---

## Live Links

| Resource              | URL                                      |
| --------------------- | ---------------------------------------- |
| **Metrics Dashboard** | `http://3.234.19.0:8080/`                |
| **Server IP**         | `3.234.19.0`                             |
| **Nextcloud**         | `http://3.234.19.0`                      |

Blog Post: https://dev.to/techgirli/how-i-built-a-real-time-ddos-detection-engine-with-python-docker-and-iptablestags-devops-417g

---

## Language Choice

**Python 3.12** — chosen because:

- The `collections.deque` is perfectly suited to O(1) sliding-window eviction
- `statistics`, `math` are in the stdlib — no external dependencies for core logic
- Flask serves the dashboard with minimal boilerplate
- `subprocess` makes iptables calls straightforward
- Faster to iterate on in a time-constrained environment than Go

---

## Architecture

```
Internet
   │
   ▼
[Nginx :80] ──── JSON access log ────► [HNG-nginx-logs volume]
   │                                           │
   ▼                                           ▼ (read-only)
[Nextcloud]                          [Detector Daemon]
                                          │
                          ┌───────────────┼────────────────┐
                          ▼               ▼                ▼
                      [iptables]       [Slack]        [Dashboard :8080]
                      DROP rule        alert          metrics UI
```

See `docs/architecture.png` for the visual diagram.

---

## How the Sliding Window Works

Every incoming HTTP request produces a log line. The monitor reads these lines and pushes a parsed record onto a queue. The detector consumes the queue and does the following for each record:

```python
from collections import deque

# One deque per IP, one global deque
ip_window = deque()      # stores UNIX timestamps
global_window = deque()

WINDOW = 60   # seconds

now = record["timestamp"]
cutoff = now - WINDOW

# 1. Append the new timestamp
ip_window.append(now)

# 2. Evict all timestamps older than 60 seconds from the LEFT
#    (deque left-pop is O(1))
while ip_window and ip_window[0] < cutoff:
    ip_window.popleft()

# 3. Count = requests in the last 60 seconds
current_rate = len(ip_window)
```

No counters, no per-minute buckets — the deque IS the window. This gives an exact sliding window with no approximation.

---

## How the Baseline Works

**Window size:** 30 minutes (1 800 per-second buckets)  
**Recalculation interval:** Every 60 seconds  
**Floor values:** mean ≥ 1.0, stddev ≥ 0.5 (prevents divide-by-zero)

Every second, the number of requests in that second is recorded in a rolling `deque(maxlen=1800)`. Every 60 seconds, mean and standard deviation are computed from whatever samples are in the deque:

```python
mean   = sum(counts) / len(counts)
stddev = sqrt(sum((c - mean)**2 for c in counts) / (len(counts) - 1))
```

**Per-hour slots:** Samples are also bucketed by wall-clock hour. If the current hour has ≥ 10 minutes of data, its stats are preferred over the global 30-minute window. This means a quiet 3 AM baseline doesn't make a busy 9 AM look like an attack.

---

## How Detection Works

Two conditions are checked after every request — whichever fires first triggers an alert:

| Condition       | Formula                        | Default threshold                |
| --------------- | ------------------------------ | -------------------------------- |
| Z-score         | `(rate - mean) / stddev > 3.0` | `zscore_threshold: 3.0`          |
| Rate multiplier | `rate > 5 × mean`              | `rate_multiplier_threshold: 5.0` |

**Error surge mode:** If an IP's 4xx/5xx rate in the current window is ≥ 3× the baseline error rate, its thresholds tighten to z > 2.0 and rate > 3× mean.

All thresholds live in `detector/config.yaml` — nothing is hardcoded.

---

## How iptables Blocking Works

When a per-IP anomaly is confirmed, the daemon runs:

```bash
iptables -I INPUT -s <IP> -j DROP
```

`-I` (insert) places the rule at the top of the INPUT chain, giving it priority over any ACCEPT rules. The kernel then silently drops all packets from that IP before they reach Nginx or Nextcloud.

Unban uses:

```bash
iptables -D INPUT -s <IP> -j DROP
```

**Backoff schedule:**

- 1st ban → 10 minutes
- 2nd ban → 30 minutes
- 3rd ban → 2 hours
- 4th ban → permanent

---

## Setup — Fresh VPS to Fully Running Stack

### 1. Provision a VPS

Minimum: 2 vCPU, 2 GB RAM. Ubuntu 22.04.

### 2. Point DNS at the server

Create an A record for your dashboard subdomain (e.g. `monitor.yourdomain.com`) pointing to the VPS IP.

### 3. Install Docker

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose v2
sudo apt install -y docker-compose-plugin

# Verify
docker --version
docker compose version
```

### 4. Clone the repository

```bash
git clone https://github.com/Techgirli/ddos-detector.git
cd ddos-detector
```

### 5. Configure environment

```bash
cp .env.example .env
nano .env
add .env to .gitignore
# Fill in: DB passwords, Nextcloud admin password, SERVER_IP
```

### 6. Configure Slack webhook

1. Go to your Slack workspace → Apps → Incoming Webhooks → Add New Webhook
2. Choose a channel (e.g. `#alerts`)
3. Copy the webhook URL
4. Edit `detector/config.yaml`:
   ```yaml
   slack:
   ```

### 7. Allow dashboard port through firewall

```bash
sudo ufw allow 80/tcp
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw enable
```

### 8. Build and start the stack

```bash
docker compose pull
docker compose up -d --build

# Watch logs
docker compose logs -f detector
```

### 9. Verify everything is running

```bash
# Check all containers are up
docker compose ps

# Check Nginx is logging in JSON
docker exec hng-nginx tail -f /var/log/nginx/hng-access.log

# Check detector is processing logs
docker logs hng-detector

# Check dashboard
curl http://localhost:8080/health

# Check iptables are accessible
docker exec hng-detector iptables -L INPUT -n
```

### 10. Verify Nextcloud is accessible

Open `http://3.234.19.0/` in a browser. You should see the Nextcloud login page.

---

## File Structure

```
.
├── detector/
│   ├── main.py          # Entry point — wires all components
│   ├── monitor.py       # Nginx log tailer + JSON parser
│   ├── baseline.py      # Rolling 30-min mean/stddev engine
│   ├── detector.py      # Sliding window + anomaly detection
│   ├── blocker.py       # iptables ban/unban wrapper
│   ├── unbanner.py      # Backoff auto-unban scheduler
│   ├── notifier.py      # Slack webhook sender
│   ├── dashboard.py     # Flask metrics dashboard
│   ├── config.yaml      # All thresholds and config (no hardcoding)
│   ├── requirements.txt # Python dependencies
│   └── Dockerfile       # Container definition
├── nginx/
│   └── nginx.conf       # JSON logging + reverse proxy config
├── docs/
│   └── architecture.png # Architecture diagram
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Testing the Detection Engine

### Simulate a DDoS attack (from another machine or VPS):

```bash
# Install Apache Bench
sudo apt install -y apache2-utils

# Send 10,000 requests with 100 concurrent connections
ab -n 10000 -c 100 http://YOUR_SERVER_IP/

# Or use hey (Go-based)
hey -n 10000 -c 100 http://YOUR_SERVER_IP/
```

You should see within 10 seconds:

1. A Slack ban notification in your channel
2. The IP appearing in `iptables -L -n`
3. The IP appearing on the dashboard

### Check audit log:

```bash
docker exec hng-detector cat /var/log/detector/audit.log
```

---

## Troubleshooting

| Problem                      | Fix                                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| Detector can't read log file | Verify `HNG-nginx-logs` volume is mounted: `docker volume inspect hng-anomaly-detector_HNG-nginx-logs` |
| iptables permission denied   | Confirm `cap_add: [NET_ADMIN, NET_RAW]` and `network_mode: host` in compose                            |
| Slack alerts not sending     | Check webhook URL in `config.yaml`; test with `curl -X POST -d '{"text":"test"}' YOUR_WEBHOOK`         |
| Dashboard not accessible     | Check port 8080 is open: `sudo ufw status` and `docker ps`                                             |
| Nextcloud not starting       | Check DB is healthy: `docker compose logs db`                                                          |

---

## Blog Post

[https://dev.to/techgirli/how-i-built-a-real-time-ddos-detection-engine-with-python-docker-and-iptablestags-devops-417g]

---

## GitHub Repository

[https://github.com/YOUR_USERNAME/hng-anomaly-detector](https://github.com/Techgirli/ddos-detector)
