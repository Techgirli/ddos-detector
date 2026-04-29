import json
import os
import time
import threading
import logging
from pathlib import Path

logger = logging.getLogger("monitor")


def _parse_line(raw: str) -> dict | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        record = json.loads(raw)
        return {
            "ip":            str(record.get("source_ip", record.get("remote_addr", "unknown"))),
            "timestamp":     float(record.get("timestamp", time.time())),
            "method":        str(record.get("method", "-")),
            "path":          str(record.get("path", "/")),
            "status":        int(record.get("status", 0)),
            "response_size": int(record.get("response_size", 0)),
        }
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.debug(
            "Skipping malformed log line: %s | error: %s", raw[:120], exc)
        return None


class LogMonitor(threading.Thread):
    def __init__(self, log_path: str, out_queue, poll_interval: float = 0.05):
        super().__init__(daemon=True, name="LogMonitor")
        self.log_path = log_path
        self.out_queue = out_queue
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.lines_processed = 0
        self.lines_skipped = 0

    def stop(self):
        self._stop_event.set()

    def _open_log(self):
        path = Path(self.log_path)
        while not path.exists():
            logger.info("Waiting for log file: %s", self.log_path)
            time.sleep(2)

        fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
        fh.seek(0, os.SEEK_END)
        logger.info("Opened log file %s at offset %d",
                    self.log_path, fh.tell())
        return fh

    def _file_was_rotated(self, fh) -> bool:
        try:
            current_pos = fh.tell()
            file_size = os.path.getsize(self.log_path)
            return current_pos > file_size
        except OSError:
            return True

    def run(self):
        logger.info("LogMonitor starting, tailing %s", self.log_path)
        fh = self._open_log()

        while not self._stop_event.is_set():
            # Check for log rotation
            if self._file_was_rotated(fh):
                logger.warning(
                    "Log rotation detected — re-opening %s", self.log_path)
                fh.close()
                fh = self._open_log()

            line = fh.readline()

            if line:
                record = _parse_line(line)
                if record:
                    self.out_queue.put(record)
                    self.lines_processed += 1
                else:
                    self.lines_skipped += 1
            else:
                # No new data — yield CPU briefly
                time.sleep(self.poll_interval)

        fh.close()
        logger.info("LogMonitor stopped")
