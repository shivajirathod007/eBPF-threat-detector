"""Rules over normalized kernel events."""

import errno
import os
from collections import OrderedDict

SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
WEB_PARENTS = {"nginx", "apache2", "httpd", "python3", "php-fpm"}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9001, 6666}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
WINDOW_NS = 3_000_000_000


class Detector:
    def __init__(self):
        self.connections = OrderedDict()

    def match(self, event):
        action, comm, uid = (event[key] for key in ("type", "comm", "uid"))
        if action == "EXEC":
            path = event["path"]
            binary = os.path.basename(path)
            parent = event["parent_comm"]
            if binary in SHELLS and parent in WEB_PARENTS:
                yield "shell_from_webserver", f"{parent} requested execution of {path}"
            if path.startswith(TEMP_DIRS):
                yield "exec_from_tmp", f"Execution requested for {path}"
            if binary in {"nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"}:
                yield "netcat_execution", f"Execution requested for {path}"

        elif action == "OPEN":
            path = event["path"]
            flags = event["flags"]
            write = bool(flags & (os.O_ACCMODE | os.O_CREAT | os.O_TRUNC))
            read = flags & os.O_ACCMODE != os.O_WRONLY and not flags & os.O_PATH
            if uid and read and path in {"/etc/shadow", "/etc/gshadow"}:
                yield "sensitive_file_read", f"{comm} (UID {uid}) attempted read access to {path}"
            if write and (path.startswith(".ssh/") or "/.ssh/" in path) and path.endswith("/authorized_keys"):
                yield "ssh_key_tampering", f"{comm} attempted write access to {path}"
            if write and (path.startswith(("/etc/cron.", "/etc/cron/", "/var/spool/cron/")) or
                          os.path.basename(path) == "crontab"):
                yield "cron_persistence", f"{comm} attempted write access to {path}"

        elif action == "CONNECT":
            port = event["dst_port"]
            peer = f'{event["dst_ip"]}:{port}'
            key = (event["pid"], event["process_start"], event["fd"])
            self.connections.pop(key, None)
            if event["result"] in (0, -errno.EINPROGRESS):
                self.connections[key] = (event["ktime_ns"], peer, event["event_id"])
                if len(self.connections) > 8192:
                    self.connections.popitem(last=False)
            if port in SUSPICIOUS_PORTS:
                yield "suspicious_port_connect", f"{comm} attempted an outbound TCP connection to {peer}"

        elif action == "DUP2":
            key = (event["pid"], event["process_start"], event["oldfd"])
            recent = self.connections.get(key)
            if recent and 0 <= event["ktime_ns"] - recent[0] <= WINDOW_NS:
                self.connections.pop(key)
                event["connect_event_id"] = recent[2]
                yield "reverse_shell_pattern", (
                    f'{comm} connected to {recent[1]} and duplicated socket FD {event["oldfd"]} onto FD {event["newfd"]}'
                )

        elif action == "SETUID" and uid and event["new_uid"] == 0:
            yield "privilege_escalation", f"{comm} (UID {uid}) requested setuid(0)"

        elif action == "PTRACE" and 0 < event["target_pid"] < 2**31 and event["target_pid"] != event["pid"]:
            yield "ptrace_usage", f'{comm} called ptrace (request {event["request"]}) on PID {event["target_pid"]}'
