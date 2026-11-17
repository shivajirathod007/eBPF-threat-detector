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
    "cron_persistence": ("Cron persistence", "Write sample schedule text to a disposable crontab file.", ["cron_persistence"]),
    "netcat_exec": ("Netcat execution", "Start netcat in help mode.", ["netcat_execution"]),
    "privilege_escalation": ("Root UID request", "Attempt setuid(0) from an unprivileged process.", ["privilege_escalation"]),
    "ptrace_usage": ("Process tracing", "Attempt to trace a temporary child process.", ["ptrace_usage"]),
    "shell_from_webserver": ("Shell from Python", "Have a Python parent launch a shell that immediately exits.", ["shell_from_webserver"]),
    "reverse_shell": ("Reverse-shell behavior", "Connect to a local TCP listener and duplicate the socket onto stdout.", ["suspicious_port_connect", "reverse_shell_pattern"]),
}


def mark_process(tag):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(15, ctypes.c_char_p(tag.encode()), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Could not mark simulation process")
    return libc


def run_scenario(name, tag, directory):
    if name == "shell_from_webserver":
        child = os.fork()
        if child == 0:
            mark_process(tag)
            os.execl("/bin/sh", "sh", "-c", "exit 0")
        _, status = os.waitpid(child, 0)
        return os.waitstatus_to_exitcode(status)

    libc = mark_process(tag)
    if name == "sensitive_file_read":
        try:
            os.close(os.open("/etc/shadow", os.O_RDONLY))
        except PermissionError:
            print("The kernel denied the expected /etc/shadow open attempt.")
    elif name == "exec_from_tmp":
        executable = directory / "demo-executable"
        shutil.copy("/bin/echo", executable)
        os.execl(executable, executable, "Temporary executable ran.")
    elif name == "ssh_key_tamper":
        keys = directory / ".ssh" / "authorized_keys"
        keys.parent.mkdir()
        keys.write_text("# Temporary authorized_keys fixture\n")
    elif name == "cron_persistence":
        (directory / "crontab").write_text("0 * * * * /bin/true\n")
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
                elif ctypes.get_errno() != errno.EPERM:
                    raise OSError(ctypes.get_errno(), "ptrace attach failed")
            finally:
                child.kill()
    elif name == "reverse_shell":
        with socket.socket() as listener, socket.socket() as client:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 4444))
            listener.listen(1)
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
                print("The local listener received the test message.")
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
                os.killpg(child.pid, signal.SIGKILL)
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
