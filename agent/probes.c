#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/errno.h>

enum event_type { EXEC = 1, OPEN, CONNECT, DUP2, SETUID, PTRACE };

struct data_t {
    u64 ktime_ns;
    u64 process_start;
    u64 cgroup_id;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 type;
    u32 arg1;
    u32 arg2;
    u32 ipv4;
    s32 result;
    char comm[16];
    char parent_comm[16];
    char path[256];
};

struct endpoint {
    int fd;
    u32 ip;
    u16 port;
    u8 tcp4;
};

struct redirection {
    u32 oldfd;
    u32 newfd;
};

BPF_PERF_OUTPUT(events);
BPF_TABLE("lru_hash", u64, struct endpoint, endpoints, 8192);
BPF_TABLE("lru_hash", u64, struct redirection, redirections, 8192);

static __always_inline int is_sensor(void) {
    return (bpf_get_current_pid_tgid() >> 32) == SENSOR_PID;
}

static __always_inline void identify(struct data_t *data, u32 type) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->ktime_ns = bpf_ktime_get_ns();
    data->process_start = task->group_leader->start_time;
    data->cgroup_id = bpf_get_current_cgroup_id();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent->tgid;
    data->uid = (u32)bpf_get_current_uid_gid();
    data->type = type;
    bpf_get_current_comm(data->comm, sizeof(data->comm));
    bpf_probe_read_kernel(data->parent_comm, sizeof(data->parent_comm), task->real_parent->comm);
}

// The syscall__ prefix tells BCC to unwrap syscall arguments on Ubuntu x86-64.
int syscall__execve(struct pt_regs *ctx, const char *filename) {
    if (is_sensor()) return 0;
    struct data_t data = {};
    identify(&data, EXEC);
    bpf_probe_read_user_str(data.path, sizeof(data.path), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char *filename, int flags) {
    if (is_sensor()) return 0;
    struct data_t data = {};
    identify(&data, OPEN);
    data.arg1 = flags;
    bpf_probe_read_user_str(data.path, sizeof(data.path), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__connect(struct pt_regs *ctx, int fd) {
    if (is_sensor()) return 0;
    u64 thread = bpf_get_current_pid_tgid();
    struct endpoint peer = {.fd = fd};
    endpoints.update(&thread, &peer);
    return 0;
}

// At TCP connect entry the requested peer is in the sockaddr argument.
// The destination fields on struct sock have not been populated yet.
int trace_tcp4(struct pt_regs *ctx, void *sk, struct sockaddr_in *address, int length) {
    u64 thread = bpf_get_current_pid_tgid();
    struct endpoint *peer = endpoints.lookup(&thread);
    if (!peer || length < sizeof(struct sockaddr_in)) return 0;
    struct sockaddr_in remote = {};
    if (bpf_probe_read_kernel(&remote, sizeof(remote), address) || remote.sin_family != AF_INET)
        return 0;
    peer->ip = remote.sin_addr.s_addr;
    peer->port = remote.sin_port;
    peer->tcp4 = 1;
    return 0;
}

int connect_return(struct pt_regs *ctx) {
    u64 thread = bpf_get_current_pid_tgid();
    struct endpoint *peer = endpoints.lookup(&thread);
    if (!peer) return 0;
    if (peer->tcp4) {
        struct data_t data = {};
        identify(&data, CONNECT);
        data.arg1 = peer->fd;
        data.arg2 = peer->port;
        data.ipv4 = peer->ip;
        data.result = PT_REGS_RC(ctx);
        events.perf_submit(ctx, &data, sizeof(data));
    }
    endpoints.delete(&thread);
    return 0;
}

static __always_inline int track_dup(u32 oldfd, u32 newfd) {
    if (newfd > 2 || oldfd == newfd || is_sensor()) return 0;
    u64 thread = bpf_get_current_pid_tgid();
    struct redirection fds = {oldfd, newfd};
    redirections.update(&thread, &fds);
    return 0;
}

int syscall__dup2(struct pt_regs *ctx, u32 oldfd, u32 newfd) {
    return track_dup(oldfd, newfd);
}

int syscall__dup3(struct pt_regs *ctx, u32 oldfd, u32 newfd) {
    return track_dup(oldfd, newfd);
}

int dup_return(struct pt_regs *ctx) {
    u64 thread = bpf_get_current_pid_tgid();
    struct redirection *fds = redirections.lookup(&thread);
    if (!fds) return 0;
    if ((long)PT_REGS_RC(ctx) >= 0) {
        struct data_t data = {};
        identify(&data, DUP2);
        data.arg1 = fds->oldfd;
        data.arg2 = fds->newfd;
        events.perf_submit(ctx, &data, sizeof(data));
    }
    redirections.delete(&thread);
    return 0;
}

int syscall__setuid(struct pt_regs *ctx, u32 uid) {
    if (is_sensor()) return 0;
    struct data_t data = {};
    identify(&data, SETUID);
    data.arg1 = uid;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__ptrace(struct pt_regs *ctx, long request, long pid) {
    if (is_sensor()) return 0;
    struct data_t data = {};
    identify(&data, PTRACE);
    data.arg1 = request;
    data.arg2 = pid;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
