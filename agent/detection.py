"""Rules over normalized kernel events."""

import errno
import os
import re
from collections import OrderedDict, defaultdict

SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
WEB_PARENTS = {"nginx", "apache2", "httpd", "gunicorn", "uvicorn"}
PHP_FPM = re.compile(r"php-fpm(?:[0-9]+(?:\.[0-9]+)*)?")
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9001, 6666}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
CRON_DIRS = ("/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/",
             "/etc/cron.monthly/", "/var/spool/cron/")
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


def matching_path(path):
    """Fold redundant separators and interior dots without resolving symlinks or '..'."""
    if "/" not in path:
        return path
    parts = path.split("/")
    prefix = "/" if path.startswith("/") else ""
    return prefix + "/".join([*(part for part in parts[:-1] if part and part != "."), parts[-1]])


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
                    pattern = match["path_regex"]
                    if not isinstance(pattern, str) or not pattern.strip():
                        raise ValueError("path_regex must be a nonempty string")
                    self.configured["OPEN"].append((name, match["access"], re.compile(pattern)))
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
            raw_path = event["path"]
            path = matching_path(raw_path)
            parent = event["parent_comm"]
            if path.startswith(TEMP_DIRS) and ".." not in path.split("/"):
                yield "exec_from_tmp", f"Execution requested for {raw_path}"
            if event.get("path_truncated"):
                return
            binary = os.path.basename(path)
            if binary in SHELLS and (parent in WEB_PARENTS or PHP_FPM.fullmatch(parent)):
                yield "shell_from_webserver", f"{parent} requested execution of {raw_path}"
            if binary in {"nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"}:
                yield "netcat_execution", f"Execution requested for {raw_path}"

        elif action == "OPEN":
            raw_path = event["path"]
            if not raw_path or event.get("path_truncated"):
                return
            path = matching_path(raw_path)
            read, write = open_access(event["flags"])
            if uid and read and path in {"/etc/shadow", "/etc/gshadow"}:
                yield "sensitive_file_read", f"{comm} (UID {uid}) attempted read access to {raw_path}"
            if write and os.path.basename(path) in {"authorized_keys", "authorized_keys2"}:
                if os.path.basename(os.path.dirname(path)) == ".ssh":
                    yield "ssh_key_tampering", f"{comm} attempted write access to {raw_path}"
            if write and (path == "/etc/crontab" or
                          (path.startswith(CRON_DIRS) and not path.endswith(("/", "/.")) and ".." not in path.split("/"))):
                yield "cron_persistence", f"{comm} attempted write access to {raw_path}"
            for name, access, pattern in self.configured["OPEN"]:
                if (read if access == "read" else write) and pattern.fullmatch(path):
                    yield name, f"{comm} attempted {access} access to {raw_path}"

        elif action == "CONNECT":
            port = event["dst_port"]
            address = event["dst_ip"]
            peer = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
            inode = event.get("socket_inode")
            if inode and event["result"] in (0, -errno.EINPROGRESS):
                key = (event["pid"], event["process_start"], inode)
                self.connections.pop(key, None)
                self.connections[key] = (event["ktime_ns"], peer, event["event_id"], event["result"])
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
                connection = "connected to" if recent[3] == 0 else "started a TCP connection to"
                yield "reverse_shell_pattern", (
                    f'{comm} {connection} {recent[1]} and duplicated socket FD {event["oldfd"]} onto FD {event["newfd"]}'
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
