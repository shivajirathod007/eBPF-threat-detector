#!/usr/bin/env python3
"""Load BCC probes and publish recent runtime telemetry."""

import json
import logging
import os
from collections import Counter, OrderedDict, deque
from datetime import datetime, timezone
from heapq import heappop, heappush
from itertools import count
from logging.handlers import RotatingFileHandler
from pathlib import Path
import signal
import socket
from threading import Event, Lock, Thread
import time
from uuid import uuid4

import yaml

from agent.dashboard_server import Dashboard
from agent.detection import Detector

BASE = Path(__file__).resolve().parent.parent
EVENT_NAMES = {1: "EXEC", 2: "OPEN", 3: "CONNECT", 4: "DUP2", 5: "SETUID", 6: "PTRACE"}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
ACTIVITY_BUCKETS = 180  # Fifteen minutes in five-second intervals


def load_rules(path):
    with path.open() as file:
        data = yaml.safe_load(file)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError(f"{path} must contain a rules list")
    rules = {}
    for entry in data["rules"]:
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(key), str) and entry[key].strip() for key in ("name", "description", "severity", "mitre")
        ):
            raise ValueError(f"{path}: every rule needs a name, description, severity and MITRE ID")
        name = entry["name"]
        if name in rules:
            raise ValueError(f"{path}: duplicate rule {name}")
        if entry["severity"] not in SEVERITIES:
            raise ValueError(f"{path}: invalid severity for {name}")
        rules[name] = entry
    return rules


def json_log(name):
    folder = BASE / "logs"
    folder.mkdir(exist_ok=True)
    logger = logging.getLogger(f"telemetry.{name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(RotatingFileHandler(folder / f"{name}.jsonl", maxBytes=8 * 1024 * 1024,
                                          backupCount=3, encoding="utf-8"))
    return logger


def normalize(raw, wall_offset):
    event_type = EVENT_NAMES[raw.type]
    event = {
        "ts": wall_offset + raw.ktime_ns / 1e9,
        "ktime_ns": raw.ktime_ns,
        "type": event_type, "pid": raw.pid, "ppid": raw.ppid, "uid": raw.uid,
        "comm": raw.comm.decode("utf-8", "replace"),
        "parent_comm": raw.parent_comm.decode("utf-8", "replace"),
        "cgroup_id": str(raw.cgroup_id), "process_start": raw.process_start,
    }
    if event_type in ("EXEC", "OPEN"):
        event["path"] = raw.path.decode("utf-8", "replace")
        if raw.arg2:
            event["path_truncated"] = True
    if event_type == "OPEN":
        event["flags"] = raw.arg1
    elif event_type == "CONNECT":
        address = bytes(raw.address[:4 if raw.family == socket.AF_INET else 16])
        event.update(fd=raw.arg1, dst_ip=socket.inet_ntop(raw.family, address),
                     dst_port=socket.ntohs(raw.arg2), result=raw.result)
    elif event_type == "DUP2":
        event.update(oldfd=raw.arg1, newfd=raw.arg2)
    elif event_type == "SETUID":
        event["new_uid"] = raw.arg1
    elif event_type == "PTRACE":
        event.update(request=raw.arg1, target_pid=raw.arg2)
    if event_type in ("CONNECT", "DUP2") and raw.socket_inode:
        event["socket_inode"] = str(raw.socket_inode)
    return event


class Telemetry:
    def __init__(self, alert_log=None, event_log=None):
        self.lock = Lock()
        self.session = uuid4().hex
        self.started = time.monotonic()
        self.wall_offset = time.time() - self.started
        self.alerts = deque(maxlen=500)
        self.events = deque(maxlen=1000)
        self.stats = Counter(events=0, alerts=0, dropped=0)
        self.severity = dict.fromkeys(SEVERITIES, 0)
        self.activity = OrderedDict()
        self.alert_log = alert_log
        self.event_log = event_log
        self.rules = load_rules(BASE / "rules/rules.yaml")
        self.detector = Detector(self.rules)
        self.rule_activity = {}
        self.probes = 0
        self.drills = {}

    def record(self, event):
        with self.lock:
            self.stats["events"] += 1
            event["event_id"] = self.stats["events"]
            matches = [self.alert(rule, detail, event) for rule, detail in self.detector.match(event)]
            self.events.appendleft(event)
            # Index by reception time so late perf records land in the current chart bucket.
            bucket = int(time.monotonic()) // 5
            activity = self.activity.setdefault(bucket, [0, 0])
            activity[0] += 1
            activity[1] += len(matches)
            while next(iter(self.activity)) <= bucket - ACTIVITY_BUCKETS:
                self.activity.popitem(last=False)
        for alert in matches:
            if self.alert_log:
                self.alert_log.info(json.dumps(alert))
            logging.info("%s %s (PID %s)", alert["severity"], alert["rule"], alert["pid"])
        if self.event_log:
            self.event_log.info(json.dumps(event))

    def alert(self, rule_key, detail, event):
        rule = self.rules[rule_key]
        self.stats["alerts"] += 1
        self.severity[rule["severity"]] += 1
        alert = {
            "alert_id": self.stats["alerts"], "event_id": event["event_id"],
            "timestamp": datetime.fromtimestamp(event["ts"], timezone.utc).isoformat(),
            "rule": rule_key, "severity": rule["severity"], "mitre": rule["mitre"], "detail": detail,
            **{field: event[field] for field in ("pid", "ppid", "comm", "uid", "cgroup_id", "process_start")},
        }
        rule_activity = self.rule_activity.setdefault(rule_key, {"count": 0, "last_seen": alert["timestamp"]})
        rule_activity["count"] += 1
        rule_activity["last_seen"] = max(rule_activity["last_seen"], alert["timestamp"])
        if "connect_event_id" in event:
            alert["connect_event_id"] = event["connect_event_id"]
        self.alerts.appendleft(alert)
        drill = self.drills.get(alert["comm"])
        if drill is not None and rule_key in drill["expected"]:
            if rule_key not in drill["alerts"]:
                drill["alerts"][rule_key] = alert
                drill["events"][event["event_id"]] = event
                connection_id = event.get("connect_event_id")
                if connection_id and connection_id not in drill["events"]:
                    connection = next((item for item in self.events if item["event_id"] == connection_id), None)
                    if connection:
                        drill["events"][connection_id] = connection
                if len(drill["alerts"]) == len(drill["expected"]):
                    drill["observed"].set()
        return alert

    def lost(self, count):
        with self.lock:
            self.stats["dropped"] += count

    def snapshot(self, include_records=False):
        with self.lock:
            now = time.monotonic()
            bucket = int(now) // 5
            activity = [self.activity.get(index, [0, 0]).copy()
                        for index in range(bucket - ACTIVITY_BUCKETS + 1, bucket + 1)]
            stats = {
                **self.stats, "ready": bool(self.probes), "probes": self.probes, "rules": len(self.rules),
                "uptime_sec": int(now - self.started), "session": self.session,
                "severity": self.severity.copy(),
                "activity": activity[-24:], "activity_history": activity,
                "rule_activity": {name: totals.copy() for name, totals in self.rule_activity.items()},
            }
            if include_records:
                return {"stats": stats, "events": list(self.events), "alerts": list(self.alerts)}
            return stats


def monitor(telemetry, stop):
    from bcc import BPF

    source = BASE / "agent/probes.c"
    bpf = BPF(src_file=str(source), cflags=[f"-DSENSOR_PID={os.getpid()}"])
    try:
        syscalls = ("execve", "execveat", "open", "openat", "openat2", "creat",
                    "setuid", "ptrace", "connect", "dup2", "dup3")
        for name in syscalls:
            bpf.attach_kprobe(event=bpf.get_syscall_fnname(name), fn_name=f"syscall__{name}")
        bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp4")
        with open("/proc/kallsyms", "rb") as symbols:
            ipv6 = any(line.split()[2] == b"tcp_v6_connect" for line in symbols)
        if ipv6:
            bpf.attach_kprobe(event="tcp_v6_connect", fn_name="trace_tcp6")
        else:
            logging.warning("tcp_v6_connect is unavailable. Socket monitoring covers IPv4.")
        bpf.attach_kretprobe(event=bpf.get_syscall_fnname("connect"), fn_name="connect_return", maxactive=256)
        for name in ("dup2", "dup3"):
            bpf.attach_kretprobe(event=bpf.get_syscall_fnname(name), fn_name="dup_return", maxactive=128)

        buffer = bpf["events"]
        pending = []
        arrival_order = count()
        decode_error = None

        def handle_event(cpu, data, size):
            nonlocal decode_error
            try:
                event = normalize(buffer.event(data), telemetry.wall_offset)
            except Exception as error:
                # ctypes swallows exceptions escaping Python perf callbacks.
                decode_error = error
                return
            heappush(pending, (event["ktime_ns"], next(arrival_order), event))

        buffer.open_perf_buffer(handle_event, page_cnt=64, lost_cb=telemetry.lost)
        telemetry.probes = len(syscalls) + 4 + int(ipv6)
        with Dashboard(telemetry, BASE / "dashboard", int(os.environ.get("PORT", "8080"))) as server:
            logging.info("Attached %s probes. Dashboard listening on port %s.", telemetry.probes, server.server_port)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                while not stop.is_set():
                    bpf.perf_buffer_poll(timeout=50)
                    if decode_error is not None:
                        raise RuntimeError("Could not decode a kernel event") from decode_error
                    # Perf buffers drain per CPU. Briefly reorder records by their kernel timestamp.
                    watermark = time.monotonic_ns() - 50_000_000
                    while pending and (pending[0][0] <= watermark or len(pending) > 4096):
                        telemetry.record(heappop(pending)[2])
            finally:
                while pending:
                    telemetry.record(heappop(pending)[2])
                server.shutdown()
                thread.join()
    finally:
        bpf.cleanup()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stopping = Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopping.set())
    telemetry = Telemetry(json_log("alerts"), json_log("events") if os.getenv("LOG_EVENTS") == "1" else None)
    monitor(telemetry, stopping)
