import errno
import os
import socket
from collections import deque
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent.agent import Telemetry, normalize
from agent.dashboard_server import lab_host
from agent.detection import Detector
from attacks.scenarios import LOOPBACK_PORTS, SCENARIOS


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

    def connect(self, result=0, address="192.168.56.1"):
        return self.record("CONNECT", fd=5, dst_ip=address, dst_port=4444, result=result, socket_inode="77")

    def rules(self):
        return [alert["rule"] for alert in self.telemetry.alerts]

    def test_tcp_peer_decoding(self):
        for family, address in ((socket.AF_INET, "192.168.56.1"), (socket.AF_INET6, "::1")):
            with self.subTest(address=address):
                raw = SimpleNamespace(type=3, ktime_ns=3, pid=1, ppid=0, uid=1000,
                                      comm=b"bash", parent_comm=b"sshd", cgroup_id=20, process_start=2,
                                      arg1=9, arg2=socket.htons(4444), result=0, family=family,
                                      address=socket.inet_pton(family, address), socket_inode=77)
                event = normalize(raw, 0)
                self.assertEqual((event["dst_ip"], event["dst_port"], event["fd"]), (address, 4444, 9))
                self.assertEqual(event["socket_inode"], "77")

    def test_same_socket_generates_one_critical_alert_with_both_events(self):
        connection = self.connect(-errno.EINPROGRESS, address="::1")
        self.record("DUP2", oldfd=5, newfd=0, socket_inode="76")  # reused descriptor
        self.record("DUP2", oldfd=5, newfd=0)  # non-socket descriptor
        self.record("DUP2", oldfd=5, newfd=1, process_start=81, socket_inode="77")  # reused PID
        redirection = self.record("DUP2", oldfd=8, newfd=1, socket_inode="77")  # alias of the TCP socket
        self.record("DUP2", oldfd=5, newfd=2, socket_inode="77")
        self.assertEqual(self.rules(), ["reverse_shell_pattern", "suspicious_port_connect"])
        alert = self.telemetry.alerts[0]
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["event_id"], redirection["event_id"])
        self.assertEqual(alert["connect_event_id"], connection["event_id"])
        self.assertIn("[::1]:4444", alert["detail"])

    def test_old_connections_and_failed_attempts_do_not_correlate(self):
        self.connect(-errno.ECONNREFUSED)
        self.record("DUP2", oldfd=5, newfd=1, socket_inode="77")
        self.connect()
        self.record("DUP2", ns=4_000_000_001, oldfd=5, newfd=1, socket_inode="77")
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

    def test_configured_file_rules_match_the_intended_paths_and_access(self):
        cases = (
            ("systemd_unit_write", "/etc/systemd/system/printer.service.d/settings.conf", os.O_WRONLY, "/etc/systemd/systematic/demo.service", os.O_RDONLY),
            ("dynamic_loader_tampering", "/etc/ld.so.preload", os.O_WRONLY, "/etc/ld.so.preload.bak", os.O_RDONLY),
            ("sudoers_write", "/etc/sudoers.d/lab", os.O_WRONLY, "/etc/sudoers.bak", os.O_RDONLY),
            ("shell_profile_write", "/home/test/.bashrc", os.O_WRONLY, "/home/test/.bashrc.bak", os.O_RDONLY),
            ("ssh_private_key_access", "/home/test/.ssh/id_ed25519", os.O_RDONLY, "/home/test/.ssh/id_ed25519.pub", os.O_WRONLY),
            ("proc_memory_access", "/proc/123/mem", os.O_RDONLY, "/proc/123/maps", os.O_WRONLY),
        )
        for rule, path, flags, ignored, wrong_access in cases:
            with self.subTest(rule=rule):
                self.telemetry.alerts.clear()
                self.record("OPEN", path=ignored, flags=flags)
                self.record("OPEN", path=path, flags=wrong_access)
                self.record("OPEN", path=path, flags=os.O_PATH | os.O_CREAT)
                self.assertEqual(self.rules(), [])
                self.record("OPEN", path=path, flags=flags)
                self.assertEqual(self.rules(), [rule])

    def test_ptrace_write_rule_uses_request_and_keeps_namespace_pid(self):
        self.record("PTRACE", request=0, target_pid=16)
        self.record("PTRACE", request=5, target_pid=0)
        self.assertEqual(self.rules(), [])
        self.record("PTRACE", request=16, target_pid=250)
        self.assertEqual(self.rules(), ["ptrace_usage"])
        self.record("PTRACE", request=5, target_pid=4)
        self.assertEqual(self.rules()[:2], ["ptrace_memory_write", "ptrace_usage"])
        self.assertIn("namespace PID 4", self.telemetry.alerts[0]["detail"])

    def test_invalid_yaml_match_fails_when_loading_rules(self):
        rules = self.telemetry.rules | {"invalid": {"match": {"event": "OPEN", "access": "write", "path_regex": "["}}}
        with self.assertRaisesRegex(ValueError, "Invalid match for rule invalid"):
            Detector(rules)

    def test_simulations_cover_every_rule_and_use_configured_ports(self):
        self.assertEqual({name for _, _, names in SCENARIOS.values() for name in names}, self.telemetry.rules.keys())
        for port in LOOPBACK_PORTS:
            event = self.record("CONNECT", fd=5, dst_ip="127.0.0.1", dst_port=port, result=-errno.ECONNREFUSED)
            self.assertEqual(self.telemetry.alerts[0]["event_id"], event["event_id"])
            self.assertEqual(self.telemetry.alerts[0]["rule"], "suspicious_port_connect")

    def test_http_host_header_accepts_numeric_addresses_and_localhost(self):
        for host in ("localhost:8080", "192.168.56.101:8080", "[::1]:8080"):
            self.assertTrue(lab_host(host))
        for host in ("", "attacker.example:8080", "attacker@example.com", "127.0.0.1:bogus", "localhost\t"):
            self.assertFalse(lab_host(host))

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
