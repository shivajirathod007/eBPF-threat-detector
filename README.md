# Runtime Watch

Runtime Watch is an eBPF threat detector for an Ubuntu Server lab. The BCC agent observes host-kernel activity, evaluates ten MITRE ATT&CK-mapped rules, and serves a live dashboard. The project is by Shivaji Rathod, Archit Dandavate, Prathmesh Surywanshi, and Athrav Bhajan.

## Start on the Ubuntu VM

The original VirtualBox setup used Ubuntu Server 24.04, user `shivazz`, host-only interface `enp0s8`, host-only IP `192.168.56.101`, and SSH port `22`. Check the VM’s IPv4 addresses before deploying. The default VirtualBox NAT address `10.0.2.15` belongs to the NAT interface.

If moving the project through the `Shared_Data` VirtualBox share, mount it in Ubuntu and work from a copy on the VM disk.

```bash
sudo mkdir -p /mnt/shared
sudo mount -t vboxsf Shared_Data /mnt/shared
ls -lah /mnt/shared
```

Copy the updated `ebpf-threat-detector` directory or extract the updated ZIP to your home directory. Run the remaining commands from the directory containing `docker-compose.yml`. The earlier ZIP used `~/ebpf-threat-detector/ebpf-threat-detector`. A `vboxsf` mount error can indicate missing VirtualBox Guest Additions.

On the VM, check Docker and install the headers matching the **running** kernel. The Compose configuration uses Linux host PID sharing and is aimed at the Ubuntu x86-64 lab from the report.

```bash
uname -r
ip -4 -br addr
sudo systemctl start docker
sudo docker compose version
sudo apt-get update
sudo apt-get install -y "linux-headers-$(uname -r)"
test -f "/lib/modules/$(uname -r)/build/Makefile"
```

If a Docker installation only provides the standalone `docker-compose` binary, use the Compose plugin for these commands. Follow the [Docker Engine instructions for Ubuntu](https://docs.docker.com/engine/install/ubuntu/) if Docker or the plugin is missing.

Create the configuration file on the VM. For direct browser access, set `DASHBOARD_BIND` to its *current host-only IP*. For example, the previous lab uses these settings.

```bash
cp -n .env.example .env
nano .env
```

```dotenv
DASHBOARD_BIND=192.168.56.101
DASHBOARD_PORT=8080
LOG_EVENTS=0
```

Build and start both containers.

```bash
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=100
curl -fsS http://192.168.56.101:8080/api/health
```

Open **http://192.168.56.101:8080** on your host or Kali machine, using the configured IP and port. The health endpoint returns `{"ready": true, "probes": 11}` after the probes attach. To reuse the earlier Compose project, run the commands from its existing project directory, or stop the earlier instance before publishing the same port.

For access over SSH, leave `DASHBOARD_BIND=127.0.0.1` and run the tunnel on your host or Kali machine. Then open **http://127.0.0.1:8080** from that machine.

```bash
ssh -N -L 8080:127.0.0.1:8080 shivazz@192.168.56.101
```

The dashboard is a single-user lab interface with HTTP and no login. Bind it to the VirtualBox host-only interface for direct access, or keep it on loopback and use the tunnel.

## Run and verify a lab drill

1. Confirm **Sensor live** in the overview.
2. Open **Simulation lab** and run **Temporary executable**. The result should show `exec_from_tmp` as observed.
3. Run **Reverse-shell behavior**. Its internal loopback listener receives a test message. The result should show **High** `suspicious_port_connect` and **Critical** `reverse_shell_pattern`.
4. Select a detection to inspect the triggering event. The reverse-shell alert also links its preceding TCP connection. Raw event evidence is available while it remains in the recent event buffer.
5. Use the Alerts or Kernel events view to search by process, rule, or PID. The feed can be paused while session metrics continue updating.

## Investigate and export a session

- Switch between events and alerts in the activity chart and select a 2-, 5-, or 15-minute window.
- Select a severity to filter the recent alerts. Open an alert to mark it reviewed, jump to recent events from that process, or export the available evidence. Review marks are stored in the current browser and scoped to the sensor session. Export JSON on the feed downloads all matching buffered records.
- Open **Rule coverage** for per-rule alert totals and last-seen times since sensor start. Select an observed rule to find its recent alerts.
- In **Simulation lab**, select **Run all scenarios** to queue the drills one at a time. You can stop after the current drill. The run history keeps up to 30 results in the current dashboard tab, with a JSON export for saving the report.

The simulation service runs as UID 10001 with dropped Linux capabilities, a read-only root filesystem, and a temporary scratch directory. Its nine drills cover all ten rules. They use real syscalls, temporary SSH-key and cron files, and a local TCP connection. Browser runs report both the command exit status and the expected rules observed for that run.

To trigger the same activity from your host or Kali machine **against the Ubuntu VM itself**, SSH into Ubuntu as an unprivileged user and run the project script there. Configure `openssh-server` on the VM if you want this workflow. The dashboard’s older browser SSH terminal has been replaced by the simulation lab. Use your SSH client for interactive host commands.

```bash
ssh shivazz@192.168.56.101
cd ~/ebpf-threat-detector/ebpf-threat-detector  # adjust to your actual project directory
./attacks/run_local_attacks.sh exec_from_tmp
./attacks/run_local_attacks.sh
```

The full VM-side script needs `python3` and `netcat-openbsd`. See [remote lab exercises](attacks/kali_remote_attacks.md) for a host-to-VM test and an external TCP listener exercise.

## Components and evidence

| Component | Configuration |
| --- | --- |
| Detector | Ubuntu 24.04 image, BCC, privileged and sharing the Ubuntu VM PID namespace |
| Dashboard | Port `8080` in the detector, mapped to the host IP and port in `.env` |
| Simulator | Unprivileged Ubuntu service on a private Docker network with no published port |
| Rules | `rules/rules.yaml` supplies alert severity and ATT&CK IDs. Match logic is in `agent/detection.py`. |
| Recent evidence | 500 alerts and 1,000 raw events in memory per sensor session |
| Disk logs | Rotating `logs/alerts.jsonl`. Set `LOG_EVENTS=1` to also write rotating `logs/events.jsonl`. Each log retains the current file and three 8 MiB backups. |

The probes observe `execve`, `openat`, IPv4 TCP connections, `dup2`/`dup3`, `setuid`, and `ptrace`. An event includes the host PID, parent process, UID and numeric cgroup ID. Alert records include the originating event ID. File, execution, UID-change and tracing findings report requests observed at syscall entry. For example, an alert on `setuid(0)` can come from a denied request.

The reverse-shell heuristic uses a successful or in-progress TCP connect and a successful redirection of the same descriptor number onto stdin, stdout or stderr from the same process within three seconds. The critical alert links both events. Rapid descriptor reuse can lead to a false match. Coverage is limited to these observed syscall patterns, including IPv4 for socket telemetry. Relative paths opened through directory descriptors may lack enough context to match. Inbound scans and SSH authentication failures require telemetry outside these probes.

The API provides `GET /api/health`, `/api/stats`, `/api/snapshot`, `/api/events`, `/api/alerts`, `/api/rules`, and `/api/simulations`. Browser drills use `POST /api/attack/<scenario>` with the `X-Lab-Action: simulate` header.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Dashboard unreachable from the host | Compare `DASHBOARD_BIND` with `ip -4 -br addr` on Ubuntu. Confirm the VM’s host-only adapter is attached and the host or Kali is on the same network. |
| Container restarts during probe loading | Read `sudo docker compose logs --tail=100 ebpf-detector`. Check the header build link, that the VM is on the expected kernel, and that tracefs is mounted with `findmnt /sys/kernel/tracing`. If needed, mount it in the VM with `sudo mount -t tracefs tracefs /sys/kernel/tracing` and recreate the service. |
| Port already in use | Check `sudo ss -lntp` on Ubuntu and stop the previous instance or set a different `DASHBOARD_PORT`. |
| Run completes with missing evidence | Check **Sensor live**, the run’s exit status, and the perf records lost counter. Review `sudo docker compose logs --tail=100 ebpf-detector simulator`. Run the temporary executable test first to establish baseline detection. |

Apply changes from `.env` with `sudo docker compose up -d`. Rebuild after changes to the code, rules, or UI with `sudo docker compose up -d --build`. Stop the stack with `sudo docker compose down`.
# eBPF-threat-detector
