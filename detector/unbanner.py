import time
import threading
import logging
from dataclasses import dataclass

logger = logging.getLogger("unbanner")


@dataclass
class BanRecord:
    ip: str
    ban_count: int = 0
    ban_time: float = 0.0
    unban_time: float = 0.0
    condition: str = ""
    rate: float = 0.0
    mean: float = 0.0
    stddev: float = 0.0


class AutoUnbanner(threading.Thread):
    def __init__(
        self,
        backoff_schedule: list,
        blocker,
        audit_fn=None,
        notify_fn=None,
        check_interval: int = 10,
    ):
        super().__init__(daemon=True, name="AutoUnbanner")

        self._stop = threading.Event()
        self._lock = threading.RLock()

        self.backoff_schedule = backoff_schedule
        self.blocker = blocker
        self.audit_fn = audit_fn or (lambda msg: logger.info(msg))
        self.notify_fn = notify_fn or (lambda msg: logger.warning(
            "Slack notifier not configured: %s", msg
        ))

        self.check_interval = check_interval
        self._records: dict[str, BanRecord] = {}

    def register_ban(
        self,
        ip: str,
        condition: str = "",
        rate: float = 0,
        mean: float = 0,
        stddev: float = 0,
    ):
        with self._lock:
            rec = self._records.get(ip)

            if rec is None:
                rec = BanRecord(ip=ip)
                self._records[ip] = rec

            rec.ban_count += 1
            rec.ban_time = time.time()
            rec.condition = condition
            rec.rate = rate
            rec.mean = mean
            rec.stddev = stddev

            idx = min(rec.ban_count - 1, len(self.backoff_schedule) - 1)
            duration = self.backoff_schedule[idx]

            rec.unban_time = -1 if duration == -1 else (rec.ban_time + duration)

            logger.info(
                "Ban registered: ip=%s count=%d duration=%s",
                ip,
                rec.ban_count,
                "permanent" if duration == -1 else f"{duration}s",
            )

    def is_permanent(self, ip: str) -> bool:
        with self._lock:
            rec = self._records.get(ip)
            return rec is not None and rec.unban_time == -1

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info("AutoUnbanner started (interval=%ds)", self.check_interval)

        while not self._stop.is_set():
            try:
                self._check_expired()
            except Exception as e:
                logger.error("Unban loop error: %s", e, exc_info=True)

            self._stop.wait(self.check_interval)

    def _check_expired(self):
        now = time.time()

        with self._lock:
            to_unban = [
                rec for rec in list(self._records.values())
                if rec.unban_time != -1 and now >= rec.unban_time
            ]

        for rec in to_unban:
            self._do_unban(rec, now)

    def _do_unban(self, rec: BanRecord, now: float):
        logger.info("UNBAN EXECUTING ip=%s", rec.ip)

        success = self.blocker.unban(rec.ip)

        if not success:
            logger.error("UNBAN FAILED ip=%s (iptables)", rec.ip)
            return

        with self._lock:
            self._records.pop(rec.ip, None)

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        duration_was = int(now - rec.ban_time)

        audit_msg = (
            f"[{ts}] UNBAN ip={rec.ip} | condition=auto_expire | "
            f"rate={rec.rate:.1f} | baseline={rec.mean:.2f}±{rec.stddev:.2f} | "
            f"ban_count={rec.ban_count} | duration_was={duration_was}s"
        )

        self.audit_fn(audit_msg)

        slack_msg = (
            f":unlock: *IP UNBANNED*\n"
            f"> IP: `{rec.ip}`\n"
            f"> Ban #{rec.ban_count} lasted {duration_was}s\n"
            f"> Condition: {rec.condition}\n"
            f"> Timestamp: {ts}"
        )

        self.notify_fn(slack_msg)

        logger.info(
            "UNBAN SUCCESS ip=%s duration=%ss",
            rec.ip,
            duration_was,
        )

    def get_records(self) -> list[dict]:
        with self._lock:
            now = time.time()
            result = []

            for rec in self._records.values():
                remaining = (
                    "permanent"
                    if rec.unban_time == -1
                    else f"{max(0, int(rec.unban_time - now))}s"
                )

                result.append({
                    "ip": rec.ip,
                    "ban_count": rec.ban_count,
                    "remaining": remaining,
                    "condition": rec.condition,
                    "rate": rec.rate,
                })

            return result
