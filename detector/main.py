import os
import sys
import queue
import time
import logging
import threading
import signal
import yaml

from monitor import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import AutoUnbanner
from notifier import SlackNotifier
from dashboard import Dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as fh:
        cfg = yaml.safe_load(fh)
    logger.info("Config loaded from %s", path)
    return cfg


class AuditLogger:
    def __init__(self, log_path: str):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._fh = open(log_path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, message: str):
        with self._lock:
            print(message, flush=True)
            self._fh.write(message + "\n")

    def close(self):
        self._fh.close()


def main():
    cfg = load_config(os.environ.get("DETECTOR_CONFIG", "config.yaml"))

    det_cfg = cfg["detection"]
    ban_cfg = cfg["banning"]
    srv_cfg = cfg["server"]
    slack_cfg = cfg["slack"]
    audit_cfg = cfg["audit"]
    nginx_cfg = cfg["nginx"]

    audit = AuditLogger(audit_cfg["log_path"])
    notifier = SlackNotifier(webhook_url=slack_cfg["webhook_url"])
    blocker = IPBlocker()

    baseline = BaselineEngine(
        window_minutes=det_cfg["baseline_window_minutes"],
        recalc_interval=det_cfg["baseline_recalc_interval"],
        floor_mean=det_cfg["baseline_floor_mean"],
        floor_stddev=det_cfg["baseline_floor_stddev"],
        hourly_min_seconds=det_cfg["hourly_min_seconds"],
        audit_fn=audit.write,
    )

    unbanner = AutoUnbanner(
        backoff_schedule=ban_cfg["backoff_schedule"],
        blocker=blocker,
        audit_fn=audit.write,
        notify_fn=notifier.send_raw,
    )

    def on_ip_anomaly(ip, rate, mean, stddev, condition, error_surge):
        if unbanner.is_permanent(ip):
            logger.info("IP %s is permanently banned — skipping re-ban", ip)
            return

        unbanner.register_ban(ip, condition=condition,
                              rate=rate, mean=mean, stddev=stddev)

        if blocker.ban(ip):
            rec = unbanner._records.get(ip)
            duration = -1
            if rec:
                duration = int(rec.unban_time -
                               rec.ban_time) if rec.unban_time != -1 else -1

            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            duration_str = "permanent" if duration == -1 else f"{duration}s"

            audit.write(
                f"[{ts}] BAN ip={ip} | condition={condition} | "
                f"rate={rate:.1f} | baseline={mean:.2f}±{stddev:.2f} | "
                f"duration={duration_str}"
            )
            notifier.ban_alert(
                ip=ip,
                rate=rate,
                mean=mean,
                stddev=stddev,
                condition=condition,
                duration_seconds=duration,
                error_surge=error_surge,
            )
        else:
            logger.error("Failed to ban IP %s via iptables", ip)

    def on_global_anomaly(rate, mean, stddev, condition):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        audit.write(
            f"[{ts}] GLOBAL_ANOMALY ip=global | condition={condition} | "
            f"rate={rate:.1f} | baseline={mean:.2f}±{stddev:.2f} | duration=N/A"
        )
        notifier.global_alert(rate=rate, mean=mean,
                              stddev=stddev, condition=condition)

    detector = AnomalyDetector(
        window_seconds=det_cfg["window_seconds"],
        zscore_threshold=det_cfg["zscore_threshold"],
        rate_multiplier=det_cfg["rate_multiplier_threshold"],
        error_rate_multiplier=det_cfg["error_rate_multiplier"],
        error_zscore_threshold=det_cfg["error_zscore_threshold"],
        cooldown_seconds=30,
        baseline=baseline,
        on_ip_anomaly=on_ip_anomaly,
        on_global_anomaly=on_global_anomaly,
        whitelist=cfg.get("whitelist", []),
    )

    log_queue: queue.Queue = queue.Queue(maxsize=50_000)
    monitor = LogMonitor(
        log_path=nginx_cfg["log_path"],
        out_queue=log_queue,
        poll_interval=0.05,
    )

    dash = Dashboard(
        host=srv_cfg["dashboard_host"],
        port=srv_cfg["dashboard_port"],
        detector=detector,
        baseline=baseline,
        unbanner=unbanner,
    )

    logger.info("=" * 60)
    logger.info("  HNG Anomaly Detection Engine starting...")
    logger.info("=" * 60)

    baseline.start()
    unbanner.start()
    monitor.start()
    dash.start()

    logger.info("All threads started. Processing log queue...")

    _shutdown = threading.Event()

    def _handle_signal(signum, frame):
        logger.info("Signal %d received — shutting down...", signum)
        _shutdown.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    last_heartbeat = time.time()

    while not _shutdown.is_set():
        try:
            processed = 0
            while processed < 500:
                try:
                    record = log_queue.get(timeout=0.1)
                except queue.Empty:
                    break
                baseline.record_request(record["timestamp"], record["status"])
                detector.process(record)
                processed += 1

            now = time.time()
            if now - last_heartbeat >= 60:
                qsize = log_queue.qsize()
                logger.info(
                    "Heartbeat | queue=%d | global_rate=%d | mean=%.2f | stddev=%.2f | "
                    "banned=%d | monitor_lines=%d",
                    qsize,
                    detector.global_rate,
                    baseline.mean,
                    baseline.stddev,
                    len(blocker.banned_ips()),
                    monitor.lines_processed,
                )
                last_heartbeat = now

        except Exception as exc:
            logger.error("Main loop error: %s", exc, exc_info=True)
            time.sleep(1)

    logger.info("Shutting down...")
    monitor.stop()
    baseline.stop()
    unbanner.stop()
    audit.close()
    logger.info("Shutdown complete.")


if __name__ == "__main__":
    main()
