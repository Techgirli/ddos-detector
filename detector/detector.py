import time
import threading
import logging
from collections import deque, defaultdict

logger = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(
        self,
        window_seconds: int = 60,
        zscore_threshold: float = 3.0,
        rate_multiplier: float = 5.0,
        error_rate_multiplier: float = 3.0,
        error_zscore_threshold: float = 2.0,
        cooldown_seconds: int = 30,
        baseline=None,
        on_ip_anomaly=None,
        on_global_anomaly=None,
        whitelist=None,
    ):
        self._lock = threading.RLock()
        self.window_seconds = window_seconds
        self.zscore_threshold = zscore_threshold
        self.rate_multiplier = rate_multiplier
        self.error_rate_multiplier = error_rate_multiplier
        self.error_zscore_threshold = error_zscore_threshold
        self.cooldown_seconds = cooldown_seconds
        self.baseline = baseline
        self.on_ip_anomaly = on_ip_anomaly or (lambda *a, **k: None)
        self.on_global_anomaly = on_global_anomaly or (lambda *a, **k: None)

        # Whitelist — these IPs are NEVER banned
        self._whitelist = set(whitelist or [
            "127.0.0.1",
            "::1",
            "172.19.0.1",
            "172.18.0.1",
            "172.20.0.1",
        ])

        self._ip_windows: dict[str, deque] = defaultdict(deque)
        self._ip_error_windows: dict[str, deque] = defaultdict(deque)
        self._global_window: deque = deque()
        self._last_alert: dict[str, float] = {}
        self._last_global_alert: float = 0.0

        self.global_rate: int = 0
        self.ip_rates: dict[str, int] = {}

    def process(self, record: dict):
        ip = record["ip"]

        # Never flag or ban whitelisted IPs
        if ip in self._whitelist:
            return

        ts = record.get("timestamp", time.time())
        status = record.get("status", 200)
        now = ts
        cutoff = now - self.window_seconds

        with self._lock:
            # Update global window
            self._global_window.append(now)
            while self._global_window and self._global_window[0] < cutoff:
                self._global_window.popleft()

            # Update per-IP window
            self._ip_windows[ip].append(now)
            while self._ip_windows[ip] and self._ip_windows[ip][0] < cutoff:
                self._ip_windows[ip].popleft()

            # Update per-IP error window
            if status >= 400:
                self._ip_error_windows[ip].append(now)
            while self._ip_error_windows[ip] and self._ip_error_windows[ip][0] < cutoff:
                self._ip_error_windows[ip].popleft()

            global_rate = len(self._global_window)
            ip_rate = len(self._ip_windows[ip])
            ip_error_rate = len(self._ip_error_windows[ip])

            self.global_rate = global_rate
            self.ip_rates[ip] = ip_rate

            mean = self.baseline.mean if self.baseline else 1.0
            stddev = self.baseline.stddev if self.baseline else 0.5
            error_mean = self.baseline.error_mean if self.baseline else 0.0

            error_surge = (
                ip_error_rate >= self.error_rate_multiplier *
                max(error_mean, 0.1)
                and ip_error_rate >= 3
            )

            z_thresh = self.error_zscore_threshold if error_surge else self.zscore_threshold
            mult_thresh = 3.0 if error_surge else self.rate_multiplier

            condition = self._check_anomaly(
                ip_rate, mean, stddev, z_thresh, mult_thresh)
            if condition and self._ip_cooldown_ok(ip, now):
                self._last_alert[ip] = now
                _ip = ip
                _rate = ip_rate
                _mean = mean
                _stddev = stddev
                _cond = condition
                _surge = error_surge
            else:
                _ip = None

            global_condition = self._check_anomaly(
                global_rate, mean, stddev, self.zscore_threshold, self.rate_multiplier
            )
            if global_condition and (now - self._last_global_alert) > self.cooldown_seconds:
                self._last_global_alert = now
                _gcond = global_condition
                _grate = global_rate
            else:
                _gcond = None
                _grate = 0

        if _ip:
            logger.warning(
                "IP anomaly: ip=%s rate=%d mean=%.2f cond=%s surge=%s",
                _ip, _rate, _mean, _cond, _surge
            )
            self.on_ip_anomaly(_ip, _rate, _mean, _stddev, _cond, _surge)

        if _gcond:
            logger.warning(
                "Global anomaly: rate=%d mean=%.2f cond=%s",
                _grate, mean, _gcond
            )
            self.on_global_anomaly(_grate, mean, stddev, _gcond)

    def get_top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        with self._lock:
            return sorted(self.ip_rates.items(), key=lambda x: x[1], reverse=True)[:n]

    def _check_anomaly(self, rate, mean, stddev, z_thresh, mult_thresh):
        if rate > mult_thresh * mean:
            return f"rate>{mult_thresh:.0f}x_mean({rate}>{mult_thresh * mean:.1f})"
        z = (rate - mean) / stddev
        if z > z_thresh:
            return f"zscore>{z_thresh}(z={z:.2f},rate={rate},mean={mean:.1f})"
        return None

    def _ip_cooldown_ok(self, ip: str, now: float) -> bool:
        last = self._last_alert.get(ip, 0.0)
        return (now - last) >= self.cooldown_seconds
