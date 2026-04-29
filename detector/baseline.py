import math
import time
import threading
import logging
from collections import deque, defaultdict

logger = logging.getLogger("baseline")


class BaselineEngine(threading.Thread):

    def __init__(
        self,
        window_minutes: int = 30,
        recalc_interval: int = 60,
        floor_mean: float = 1.0,
        floor_stddev: float = 0.5,
        hourly_min_seconds: int = 600,
        audit_fn=None,
    ):
        super().__init__(daemon=True, name="BaselineEngine")
        self._lock = threading.RLock()
        self._stop = threading.Event()

        self.recalc_interval = recalc_interval
        self.floor_mean = floor_mean
        self.floor_stddev = floor_stddev
        self.hourly_min_seconds = hourly_min_seconds
        self.audit_fn = audit_fn or (lambda msg: None)

        maxlen = window_minutes * 60

        self._samples: deque = deque(maxlen=maxlen)

        self._hourly: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=3600))

        self._current_second: int = int(time.time())
        self._current_count: int = 0
        self._current_errors: int = 0

        self.mean: float = floor_mean
        self.stddev: float = floor_stddev
        self.error_mean: float = 0.0
        self.effective_source: str = "initializing"

        self.history: list = []

    def record_request(self, timestamp: float, status: int):
        """
        Record one request.  Called from the detector thread for every
        parsed log line.
        """
        second = int(timestamp)
        is_error = 1 if status >= 400 else 0

        with self._lock:
            if second != self._current_second:
                # Flush the completed second into the rolling deque
                self._flush_second()
                self._current_second = second
                self._current_count = 0
                self._current_errors = 0

            self._current_count += 1
            self._current_errors += is_error

    def _flush_second(self):
        """Push accumulated counts for `_current_second` into all deques."""
        ts = self._current_second
        count = self._current_count
        errors = self._current_errors

        self._samples.append((count, errors))

        hour_key = time.strftime("%Y-%m-%d-%H", time.localtime(ts))
        self._hourly[hour_key].append((count, errors))

        # Prune old hourly buckets (keep only last 25 hours)
        all_keys = sorted(self._hourly.keys())
        while len(all_keys) > 25:
            del self._hourly[all_keys.pop(0)]

    def _compute_stats(self, samples) -> tuple[float, float, float]:

        if len(samples) < 2:
            return self.floor_mean, self.floor_stddev, 0.0

        counts = [s[0] for s in samples]
        errors = [s[1] for s in samples]

        n = len(counts)
        mean = sum(counts) / n
        variance = sum((c - mean) ** 2 for c in counts) / (n - 1)
        stddev = math.sqrt(variance)

        error_mean = sum(errors) / n

        mean = max(mean, self.floor_mean)
        stddev = max(stddev, self.floor_stddev)

        return mean, stddev, error_mean

    def _recalculate(self):

        with self._lock:

            self._flush_second()

            current_hour = time.strftime("%Y-%m-%d-%H")
            hourly_samples = list(self._hourly.get(current_hour, []))
            global_samples = list(self._samples)

        if len(hourly_samples) >= self.hourly_min_seconds:
            samples = hourly_samples
            source = f"hourly({current_hour}, n={len(samples)})"
        else:
            samples = global_samples
            source = f"global_30min(n={len(samples)})"

        mean, stddev, error_mean = self._compute_stats(samples)

        self.mean = mean
        self.stddev = stddev
        self.error_mean = error_mean
        self.effective_source = source

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.history.append((time.time(), mean, stddev))
        # Keep only 24 h of history points (one per minute = 1440)
        if len(self.history) > 1440:
            self.history.pop(0)

        msg = (
            f"[{ts}] BASELINE_RECALC ip=global | condition=scheduled | "
            f"rate=N/A | baseline={mean:.2f}±{stddev:.2f} | "
            f"source={source} | duration=N/A"
        )
        logger.info(
            "Baseline recalculated: mean=%.2f stddev=%.2f source=%s", mean, stddev, source)
        self.audit_fn(msg)

    def run(self):
        logger.info("BaselineEngine started (recalc every %ds)",
                    self.recalc_interval)
        # Initial short wait so we have some data
        time.sleep(max(10, self.recalc_interval))
        while not self._stop.is_set():
            try:
                self._recalculate()
            except Exception as exc:
                logger.error("Baseline recalc error: %s", exc, exc_info=True)
            self._stop.wait(self.recalc_interval)

    def stop(self):
        self._stop.set()
