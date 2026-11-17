import errno
import os
import socket
import struct
from collections import deque
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent.agent import Telemetry, normalize


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.telemetry = Telemetry()

    def record(self, action, ns=1_000_000_000, **fields):
        event = {
            "type": action, "ktime_ns": ns, "ts": 1_700_000_000 + ns / 1e9,
            "pid": 250, "ppid": 240, "uid": 1000, "comm": "test",
            "parent_comm": "python3", "cgroup_id": "42", "process_start": 80,
            **fields,
        }
        self.telemetry.record(event)
        return event

    def connect(self, result=0):
        return self.record("CONNECT", fd=5, dst_ip="192.168.56.1", dst_port=4444, result=result)

    def rules(self):
        return [alert["rule"] for alert in self.telemetry.alerts]

    def test_tcp_peer_decoding(self):
        raw = SimpleNamespace(type=3, ktime_ns=3, pid=1, ppid=0, uid=1000,
                              comm=b"bash", parent_comm=b"sshd", cgroup_id=20, process_start=2,
                              arg1=9, arg2=socket.htons(4444), result=0,
                              ipv4=struct.unpack("=I", socket.inet_aton("192.168.56.1"))[0])
        event = normalize(raw, 0)
        self.assertEqual((event["dst_ip"], event["dst_port"], event["fd"]), ("192.168.56.1", 4444, 9))

    def test_same_socket_generates_one_critical_alert_with_both_events(self):
        connection = self.connect(-errno.EINPROGRESS)
        self.record("DUP2", oldfd=7, newfd=0)
        self.record("DUP2", oldfd=5, newfd=1, process_start=81)
        redirection = self.record("DUP2", oldfd=5, newfd=1)
        self.record("DUP2", oldfd=5, newfd=2)
        self.assertEqual(self.rules(), ["reverse_shell_pattern", "suspicious_port_connect"])
        alert = self.telemetry.alerts[0]
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["event_id"], redirection["event_id"])
        self.assertEqual(alert["connect_event_id"], connection["event_id"])

    def test_old_connections_and_failed_attempts_do_not_correlate(self):
        self.connect(-errno.ECONNREFUSED)
        self.record("DUP2", oldfd=5, newfd=1)
        self.connect()
        self.record("DUP2", ns=4_000_000_001, oldfd=5, newfd=1)
        self.assertEqual(self.rules(), ["suspicious_port_connect", "suspicious_port_connect"])

    def test_file_rules_respect_write_intent_and_exact_paths(self):
        self.record("OPEN", path="/etc/shadow.bak", flags=os.O_RDONLY)
        self.record("OPEN", path="/etc/shadow", flags=os.O_PATH)
        self.record("OPEN", path="/etc/shadow", flags=os.O_RDONLY)
        self.record("OPEN", path="/home/test/.ssh/authorized_keys", flags=os.O_RDONLY)
        self.record("OPEN", path="/home/test/.ssh/authorized_keys", flags=os.O_WRONLY)
        self.record("OPEN", path="/etc/cron.d/lab", flags=os.O_CREAT | os.O_WRONLY)
        self.assertEqual(self.rules(), ["cron_persistence", "ssh_key_tampering", "sensitive_file_read"])

    def test_tmp_rule_uses_directory_boundary_and_kernel_parent(self):
        self.record("EXEC", path="/tmpfile")
        self.record("EXEC", path="/tmp/payload")
        self.record("EXEC", path="/bin/sh")
        self.assertEqual(self.rules(), ["shell_from_webserver", "exec_from_tmp"])

    def test_coverage_survives_recent_alert_eviction(self):
        self.telemetry.alerts = deque(maxlen=1)
        self.record("EXEC", ns=2_000_000_000, path="/tmp/first")
        self.record("EXEC", ns=1_000_000_000, path="/tmp/delayed")
        self.record("OPEN", path="/etc/shadow", flags=os.O_RDONLY)
        self.assertEqual(self.rules(), ["sensitive_file_read"])
        totals = self.telemetry.snapshot()["rule_activity"]["exec_from_tmp"]
        self.assertEqual(totals, {"count": 2, "last_seen": "2023-11-14T22:13:22+00:00"})

    def test_activity_uses_a_rolling_fifteen_minute_window(self):
        start = int(self.telemetry.started) // 5 * 5
        with patch("agent.agent.time.monotonic", return_value=start):
            self.record("EXEC", path="/tmp/demo")
        with patch("agent.agent.time.monotonic", return_value=start + 895):
            stats = self.telemetry.snapshot()
            self.assertEqual(len(stats["activity_history"]), 180)
            self.assertEqual(stats["activity_history"][0], [1, 1])
            self.assertEqual(sum(item[0] for item in stats["activity"]), 0)
        with patch("agent.agent.time.monotonic", return_value=start + 900):
            self.record("OPEN", path="/etc/hosts", flags=os.O_RDONLY)
            self.assertEqual(list(self.telemetry.activity.values()), [[1, 0]])
            self.assertEqual(self.telemetry.snapshot()["activity_history"][-1], [1, 0])


if __name__ == "__main__":
    unittest.main()
