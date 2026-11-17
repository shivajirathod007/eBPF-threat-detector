# Remote Ubuntu lab exercises

Use the VM’s current host-only IP and an unprivileged Ubuntu account. The original lab used `shivazz@192.168.56.101`. Open the dashboard from your host or Kali while running the commands below.

## Trigger a temporary-path execution from the host

Run this on the host or Kali after copying the updated project to Ubuntu. Use the actual project directory when it differs from the example.

```bash
ssh shivazz@192.168.56.101 'cd ~/ebpf-threat-detector/ebpf-threat-detector && ./attacks/run_local_attacks.sh exec_from_tmp'
```

The dashboard should show `exec_from_tmp`. Run the script with no scenario argument over SSH to try the full set on the VM.

## Observe an outbound connection to the host

Confirm the host or Kali IPv4 is reachable from the Ubuntu VM on the host-only network. On a Linux host or Kali with OpenBSD netcat, start a one-connection listener bound to that address.

```bash
nc -n -l 192.168.56.1 4444
```

On the Ubuntu VM, set `LAB_HOST_IP` to the host or Kali address you verified. This runs a bounded TCP and descriptor-redirection test that sends a single fixed message to the listener.

```bash
LAB_HOST_IP=192.168.56.1
python3 - "$LAB_HOST_IP" <<'PY'
import os
import socket
import sys

with socket.create_connection((sys.argv[1], 4444), timeout=3) as peer:
    os.dup2(peer.fileno(), 1)
    os.write(1, b"eBPF lab test\n")
PY
```

Look for `suspicious_port_connect` and `reverse_shell_pattern`. The listener should print the test message. In the critical alert, inspect the peer address and both event IDs. You can also use **Reverse-shell behavior** from the browser to exercise the pattern with an internal listener.
