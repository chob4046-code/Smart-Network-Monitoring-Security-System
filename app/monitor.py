import socket
import time

from .db import get_enabled_targets, save_check


def check_tcp(host, port, timeout=2.0):
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = round((time.perf_counter() - started) * 1000, 2)
            return "UP", latency, None
    except (socket.timeout, TimeoutError):
        return "DOWN", None, "Connection timed out"
    except socket.gaierror as exc:
        return "DOWN", None, f"DNS/address error: {exc}"
    except OSError as exc:
        return "DOWN", None, f"Connection failed: {exc}"


def run_monitor_cycle(db_path, timeout=2.0):
    for target in get_enabled_targets(db_path):
        status, latency, error = check_tcp(target["host"], target["port"], timeout)
        save_check(db_path, target["id"], status, latency, error)
