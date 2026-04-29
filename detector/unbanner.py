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

        # ✅ FIX: Ensure notifier always logs if not provided
        if notify_fn:
            self.notify_fn = notify_fn
        else:
            self.notify_fn = lambda msg: logger.warning(
                "Slack notifier not configured: %s", msg
            )

        self.check_interval = check_interval

        # ip → BanRecord
        self._records: dict[str, BanRecord] = {}

    # 🔥 MUST be called when banning
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

            # ✅ FIXED syntax
            rec.unban_time = -1 if duration == - \
                1 else (rec.ban_time + duration)

            duration_str = "permanent" if duration == -1 else f"{duration}s"

            logger.info(
                "Ban registered: ip=%s count=%d duration=%s",
                ip,
                rec.ban_count,
                duration_str,
            )

    def is_permanent(self, ip: str) -> bool:
        with self._lock:
            rec = self._records.get(ip)
            return rec is not None and rec.unban_time == -1

    def get_records(self) -> list[dict]:
        with self._lock:
            now = time.time()
            result = []

            for rec in self._records.values():
                if self.blocker.is_banned(rec.ip):
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

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info("AutoUnbanner started (interval=%ds)", self.check_interval)

        while not self._stop.is_set():
            try:
                self._check_expired()
            except Exception as e:
                logger.error("Unban loop error: %s", e)

            self._stop.wait(self.check_interval)

    def _check_expired(self):
        now = time.time()

        with self._lock:
            logger.debug("Checking unbans... total records=%d",
                         len(self._records))

            to_unban = [
                rec for rec in self._records.values()
                if self.blocker.is_banned(rec.ip)
                and rec.unban_time != -1
                and now >= rec.unban_time
            ]

        for rec in to_unban:
            self._do_unban(rec, now)

    def _do_unban(self, rec: BanRecord, now: float):
        logger.info("Attempting unban for ip=%s", rec.ip)

        success = self.blocker.unban(rec.ip)

        if not success:
            logger.warning("Unban failed for ip=%s", rec.ip)
            return

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        ban_count = rec.ban_count
        duration_was = int(now - rec.ban_time)

        # Audit log
        audit_msg = (
            f"[{ts}] UNBAN ip={rec.ip} | condition=auto_expire | "
            f"rate={rec.rate:.1f} | baseline={rec.mean:.2f}±{rec.stddev:.2f} | "
            f"ban_count={ban_count} | duration_was={duration_was}s"
        )
        self.audit_fn(audit_msg)

        # Next escalation duration
        next_idx = min(ban_count, len(self.backoff_schedule) - 1)
        next_dur = self.backoff_schedule[next_idx]
        next_dur_str = "permanent" if next_dur == -1 else f"{next_dur}s"

        # ✅ Slack message
        slack_msg = (
            f":unlock: *IP UNBANNED*\n"
            f">*IP:* `{rec.ip}`\n"
            f">*Ban #{ban_count}* lasted {duration_was}s\n"
            f">*Original condition:* {rec.condition}\n"
            f">*Next ban if re-triggered:* {next_dur_str}\n"
            f">*Timestamp:* {ts}"
        )

        self.notify_fn(slack_msg)

        logger.info(
            "Unbanned ip=%s after %ds (ban #%d)",
            rec.ip,
            duration_was,
            ban_count,
        )
