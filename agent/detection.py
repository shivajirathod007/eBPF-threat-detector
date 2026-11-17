"""Rules over normalized kernel events."""

import errno
import os
import re
from collections import OrderedDict, defaultdict

SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
WEB_PARENTS = {"nginx", "apache2", "httpd", "python3", "php-fpm"}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9001, 6666}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
WINDOW_NS = 3_000_000_000
BUILTIN_RULES = {
    "shell_from_webserver", "exec_from_tmp", "netcat_execution", "sensitive_file_read",
    "ssh_key_tampering", "cron_persistence", "suspicious_port_connect", "reverse_shell_pattern",
    "privilege_escalation", "ptrace_usage",
}


def open_access(flags):
    if flags & os.O_PATH:
        return False, False
    access = flags & os.O_ACCMODE
    read = access in (os.O_RDONLY, os.O_RDWR)
    write = access in (os.O_WRONLY, os.O_RDWR) or bool(flags & (os.O_CREAT | os.O_TRUNC))
    return read, write


class Detector:
    def __init__(self, rules):
        self.connections = OrderedDict()
        self.configured = defaultdict(list)
        missing = BUILTIN_RULES - rules.keys()
        if missing:
            raise ValueError(f"Missing built-in rule definitions: {', '.join(sorted(missing))}")
        for name, rule in rules.items():
            match = rule.get("match")
            if name in BUILTIN_RULES and match is None:
                continue
            try:
                if name in BUILTIN_RULES:
                    raise ValueError("built-in rules already have a matcher")
                if not isinstance(match, dict):
                    raise ValueError("additional rules require a match mapping")
                if set(match) == {"event", "access", "path_regex"} and match["event"] == "OPEN":
                    if match["access"] not in ("read", "write"):
                        raise ValueError("access must be read or write")
                    self.configured["OPEN"].append((name, match["access"], re.compile(match["path_regex"])))
                elif set(match) == {"event", "requests"} and match["event"] == "PTRACE":
                    requests = match["requests"]
                    if not isinstance(requests, list) or not requests or any(type(item) is not int or item <= 0 for item in requests):
                        raise ValueError("requests must be a nonempty list of positive ptrace request numbers")
                    self.configured["PTRACE"].append((name, frozenset(requests)))
                else:
                    raise ValueError("expected an OPEN match with access and path_regex, or a PTRACE match with requests")
            except (TypeError, ValueError, re.error) as error:
                raise ValueError(f"Invalid match for rule {name}: {error}") from error

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
            read, write = open_access(event["flags"])
            if uid and read and path in {"/etc/shadow", "/etc/gshadow"}:
                yield "sensitive_file_read", f"{comm} (UID {uid}) attempted read access to {path}"
            if write and (path.startswith(".ssh/") or "/.ssh/" in path) and path.endswith("/authorized_keys"):
                yield "ssh_key_tampering", f"{comm} attempted write access to {path}"
            if write and (path.startswith(("/etc/cron.", "/etc/cron/", "/var/spool/cron/")) or
                          os.path.basename(path) == "crontab"):
                yield "cron_persistence", f"{comm} attempted write access to {path}"
            for name, access, pattern in self.configured["OPEN"]:
                if (read if access == "read" else write) and pattern.fullmatch(path):
                    yield name, f"{comm} attempted {access} access to {path}"

        elif action == "CONNECT":
            port = event["dst_port"]
            address = event["dst_ip"]
            peer = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
            inode = event.get("socket_inode")
            if inode and event["result"] in (0, -errno.EINPROGRESS):
                key = (event["pid"], event["process_start"], inode)
                self.connections.pop(key, None)
                self.connections[key] = (event["ktime_ns"], peer, event["event_id"])
                if len(self.connections) > 8192:
                    self.connections.popitem(last=False)
            if port in SUSPICIOUS_PORTS:
                yield "suspicious_port_connect", f"{comm} attempted an outbound TCP connection to {peer}"

        elif action == "DUP2":
            key = (event["pid"], event["process_start"], event.get("socket_inode"))
            recent = self.connections.get(key)
            if recent and 0 <= event["ktime_ns"] - recent[0] <= WINDOW_NS:
                self.connections.pop(key)
                event["connect_event_id"] = recent[2]
                yield "reverse_shell_pattern", (
                    f'{comm} connected to {recent[1]} and duplicated socket FD {event["oldfd"]} onto FD {event["newfd"]}'
                )

        elif action == "SETUID" and uid and event["new_uid"] == 0:
            yield "privilege_escalation", f"{comm} (UID {uid}) requested setuid(0)"

        elif action == "PTRACE" and event["request"] and 0 < event["target_pid"] < 2**31:
            request = event["request"]
            target = event["target_pid"]
            detail = f"{comm} issued ptrace request {request} against namespace PID {target}"
            yield "ptrace_usage", detail
            for name, requests in self.configured["PTRACE"]:
                if request in requests:
                    yield name, detail
