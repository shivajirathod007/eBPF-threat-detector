"""Repeatable drills using real syscalls and disposable data."""

import argparse
import ctypes
import errno
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory

SCENARIOS = {
    "sensitive_file_read": ("Credential file access", "Attempt to open /etc/shadow as an unprivileged user.", ["sensitive_file_read"]),
    "exec_from_tmp": ("Temporary executable", "Copy and run a harmless executable from /tmp.", ["exec_from_tmp"]),
    "ssh_key_tamper": ("SSH key persistence", "Write a fixture named .ssh/authorized_keys in a disposable directory.", ["ssh_key_tampering"]),
    "cron_persistence": ("Cron persistence", "Request write access to /etc/crontab without changing it.", ["cron_persistence"]),
    "netcat_exec": ("Netcat execution", "Start netcat in help mode.", ["netcat_execution"]),
    "privilege_escalation": ("Root UID request", "Attempt setuid(0) from an unprivileged process.", ["privilege_escalation"]),
    "ptrace_usage": ("Process tracing", "Attempt to trace a temporary child process.", ["ptrace_usage"]),
    "shell_from_webserver": ("Shell from a web-service process", "Name the disposable parent nginx and launch a shell that immediately exits.", ["shell_from_webserver"]),
    "reverse_shell": ("Reverse-shell behavior", "Connect to a local TCP listener and duplicate the socket onto stdout.", ["suspicious_port_connect", "reverse_shell_pattern"]),
    "systemd_unit_write": ("Systemd service write attempt", "Request a writable descriptor for an absent service unit.", ["systemd_unit_write"]),
    "dynamic_loader_tampering": ("Dynamic linker preload attempt", "Try opening /etc/ld.so.preload for writing, without changing it.", ["dynamic_loader_tampering"]),
    "sudoers_write": ("Sudo policy write attempt", "Try opening /etc/sudoers for writing, without changing it.", ["sudoers_write"]),
    "shell_profile_write": ("Shell startup profile", "Write a comment into a disposable .bashrc fixture.", ["shell_profile_write"]),
    "ssh_private_key_access": ("SSH private key access", "Open a disposable file with a conventional SSH private key name.", ["ssh_private_key_access"]),
    "proc_memory_access": ("Process memory access", "Try opening the memory file of a disposable child process.", ["proc_memory_access"]),
    "ptrace_memory_write": ("Ptrace memory write attempt", "Issue a write request to an invalid address in a disposable, unattached process.", ["ptrace_usage", "ptrace_memory_write"]),
}

PROTECTED_PATHS = {
    "cron_persistence": "/etc/crontab",
    "systemd_unit_write": "/etc/systemd/system/runtime-watch-lab.service",
    "dynamic_loader_tampering": "/etc/ld.so.preload",
    "sudoers_write": "/etc/sudoers",
}
LOOPBACK_PORTS = (4444, 1337, 31337, 9001, 6666)


def mark_process(tag):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(15, ctypes.c_char_p(tag.encode()), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Could not mark simulation process")
    return libc


def attempt_open(path, flags):
    try:
        os.close(os.open(path, flags | os.O_NOFOLLOW))
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.EROFS, errno.ELOOP):
            raise
        print(f"Open attempt for {path}: {error.strerror}.")
    else:
        print(f"Opened and closed {path} without reading or writing contents.")


def bind_test_listener(listener):
    for port in LOOPBACK_PORTS:
        try:
            listener.bind(("127.0.0.1", port))
            return port
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
    raise OSError(errno.EADDRINUSE, "All test listener ports are occupied")


def run_scenario(name, tag, directory):
    if name == "shell_from_webserver":
        mark_process("nginx")
        child = os.fork()
        if child == 0:
            mark_process(tag)
            os.execl("/bin/sh", "sh", "-c", "exit 0")
        _, status = os.waitpid(child, 0)
        return os.waitstatus_to_exitcode(status)

    libc = mark_process(tag)
    if name == "sensitive_file_read":
        attempt_open("/etc/shadow", os.O_RDONLY)
    elif name == "exec_from_tmp":
        executable = directory / "demo-executable"
        shutil.copy("/bin/echo", executable)
        os.execl(executable, executable, "Temporary executable ran.")
    elif name == "ssh_key_tamper":
        keys = directory / ".ssh" / "authorized_keys"
        keys.parent.mkdir()
        keys.write_text("# Temporary authorized_keys fixture\n")
    elif name == "netcat_exec":
        nc = shutil.which("nc")
        if not nc:
            raise RuntimeError("Install netcat-openbsd to run this scenario.")
        os.execl(nc, nc, "-h")
    elif name == "privilege_escalation":
        try:
            os.setuid(0)
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EINVAL):
                raise
            print("The kernel denied the expected setuid(0) request.")
        else:
            raise RuntimeError("setuid(0) unexpectedly succeeded.")
    elif name == "ptrace_usage":
        with subprocess.Popen(["/bin/sleep", "5"]) as child:
            try:
                if libc.ptrace(16, child.pid, None, None) == 0:
                    os.waitpid(child.pid, os.WUNTRACED)
                    if libc.ptrace(17, child.pid, None, None) != 0:
                        raise OSError(ctypes.get_errno(), "Could not detach from the test process")
                else:
                    error = ctypes.get_errno()
                    if error != errno.EPERM:
                        raise OSError(error, "ptrace attach failed")
                    print("The kernel denied the ptrace attach request.")
            finally:
                child.kill()
    elif name == "reverse_shell":
        with socket.socket() as listener, socket.socket() as client:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            port = bind_test_listener(listener)
            listener.listen(1)
            listener.settimeout(2)
            client.settimeout(2)
            client.connect(listener.getsockname())
            with listener.accept()[0] as peer:
                peer.settimeout(2)
                saved = os.dup(1)
                try:
                    os.dup2(client.fileno(), 1)
                    os.write(1, b"eBPF lab simulation\n")
                finally:
                    os.dup2(saved, 1)
                    os.close(saved)
                if not peer.recv(128):
                    raise RuntimeError("The test listener received no data.")
                print(f"The local listener received the test message on port {port}.")
    elif name in PROTECTED_PATHS:
        attempt_open(PROTECTED_PATHS[name], os.O_WRONLY)
    elif name == "shell_profile_write":
        (directory / ".bashrc").write_text("# Disposable profile fixture\n")
    elif name == "ssh_private_key_access":
        keys = directory / ".ssh"
        keys.mkdir(mode=0o700)
        key = keys / "id_ed25519"
        key.touch(mode=0o600)
        os.close(os.open(key, os.O_RDONLY))
    elif name in {"proc_memory_access", "ptrace_memory_write"}:
        with subprocess.Popen(["/bin/sleep", "5"]) as child:
            try:
                if name == "proc_memory_access":
                    attempt_open(f"/proc/{child.pid}/mem", os.O_RDONLY)
                elif libc.ptrace(5, child.pid, None, None) != -1:
                    raise RuntimeError("An unexpected ptrace write succeeded")
                else:
                    print(f"The ptrace memory write request failed: {os.strerror(ctypes.get_errno())}.")
            finally:
                child.kill()
    else:
        raise ValueError(f"Unknown simulation {name}")
    return 0


def launch(name, tag):
    with TemporaryDirectory(prefix="ebpf-lab-", dir="/tmp") as directory:
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), name, "--worker", tag, directory],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True,
        )
        with child:
            try:
                output, _ = child.communicate(timeout=8)
                if name == "netcat_exec" and child.returncode == 0:
                    output = "Netcat help command ran."
                return {"exit_code": child.returncode, "output": output.strip()[:2000]}
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate()
                return {"exit_code": 124, "output": "The drill exceeded its execution deadline."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=[*SCENARIOS, "all"], default="all", nargs="?")
    parser.add_argument("--worker", nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.getuid() == 0 or os.geteuid() == 0:
        parser.error("Run the drills as an unprivileged user.")
    if args.worker:
        tag, directory = args.worker
        return run_scenario(args.scenario, tag, Path(directory))

    failed = False
    for name in SCENARIOS if args.scenario == "all" else [args.scenario]:
        result = launch(name, "lab-" + secrets.token_hex(5))
        print(f"{SCENARIOS[name][0]} (exit {result['exit_code']})")
        if result["output"]:
            print(result["output"])
        failed |= result["exit_code"] != 0
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
