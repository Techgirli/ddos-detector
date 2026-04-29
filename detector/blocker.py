import subprocess
import threading
import logging
import time

logger = logging.getLogger("blocker")


class IPBlocker:
    def __init__(self):
        self._lock = threading.RLock()
        self._banned: set[str] = set()    # IPs currently in iptables

    def ban(self, ip: str) -> bool:

        with self._lock:
            if ip in self._banned:
                logger.debug("IP %s already banned — skipping", ip)
                return False
            ok = self._run_iptables("-I", ip)
            if ok:
                self._banned.add(ip)
                logger.info("BANNED ip=%s", ip)
            return ok

    def unban(self, ip: str) -> bool:

        with self._lock:
            if ip not in self._banned:
                logger.debug("IP %s not in banned set — skipping unban", ip)
                return False
            ok = self._run_iptables("-D", ip)
            if ok:
                self._banned.discard(ip)
                logger.info("UNBANNED ip=%s", ip)
            return ok

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._banned

    def banned_ips(self) -> list[str]:
        with self._lock:
            return list(self._banned)

    def _run_iptables(self, action: str, ip: str) -> bool:

        cmd = ["iptables", action, "INPUT", "-s", ip, "-j", "DROP"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                logger.error(
                    "iptables %s %s failed: %s", action, ip, result.stderr.strip()
                )
                return False
            return True
        except FileNotFoundError:
            logger.warning(
                "iptables not found — ban/unban is a no-op (ip=%s)", ip)
            return True
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out for ip=%s", ip)
            return False
        except Exception as exc:
            logger.error("iptables error for ip=%s: %s", ip, exc)
            return False
