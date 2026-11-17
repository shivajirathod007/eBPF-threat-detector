#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fcntl.h>

enum event_type { EXEC = 1, OPEN, CONNECT, DUP2, SETUID, PTRACE };

struct data_t {
    u64 ktime_ns;
    u64 process_start;
    u64 cgroup_id;
    u64 socket_inode;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 type;
    u32 arg1;
    u32 arg2;
    s32 result;
    u16 family;
    u8 address[16];
    char comm[16];
    char parent_comm[16];
    char path[256];
};

struct endpoint {
    u64 socket_inode;
    int fd;
    u16 port;
    u16 family;
    u8 address[16];
};

struct redirection {
    u32 oldfd;
    u32 newfd;
    u64 socket_inode;
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

static __always_inline int trace_exec(struct pt_regs *ctx, const char *filename) {
    if (is_sensor()) return 0;
    struct data_t data = {};
    identify(&data, EXEC);
    bpf_probe_read_user_str(data.path, sizeof(data.path), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

static __always_inline int trace_open(struct pt_regs *ctx, const char *filename, u32 flags) {
    if (is_sensor()) return 0;
    struct data_t data = {};
    identify(&data, OPEN);
    data.arg1 = flags;
    bpf_probe_read_user_str(data.path, sizeof(data.path), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// The syscall__ prefix tells BCC to unwrap syscall arguments on Ubuntu x86-64.
int syscall__execve(struct pt_regs *ctx, const char *filename) {
    return trace_exec(ctx, filename);
}

int syscall__execveat(struct pt_regs *ctx, int dirfd, const char *filename) {
    return trace_exec(ctx, filename);
}

int syscall__open(struct pt_regs *ctx, const char *filename, int flags) {
    return trace_open(ctx, filename, flags);
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char *filename, int flags) {
    return trace_open(ctx, filename, flags);
}

int syscall__openat2(struct pt_regs *ctx, int dirfd, const char *filename, void *how, size_t size) {
    if (is_sensor() || size < sizeof(u64)) return 0;
    // The first member of the open_how UAPI structure contains the open flags.
    u64 flags = 0;
    if (bpf_probe_read_user(&flags, sizeof(flags), how)) return 0;
    return trace_open(ctx, filename, (u32)flags);
}

int syscall__creat(struct pt_regs *ctx, const char *filename) {
    return trace_open(ctx, filename, O_CREAT | O_WRONLY | O_TRUNC);
}

static __always_inline u64 get_socket_inode(u32 fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fdtable *table = task->files->fdt;
    if (!table || fd >= table->max_fds) return 0;
    struct file **files = table->fd;
    struct file *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), &files[fd]) || !file) return 0;
    struct inode *inode = NULL;
    if (bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode) || !inode) return 0;
    umode_t mode = 0;
    if (bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode) ||
        (mode & S_IFMT) != S_IFSOCK) return 0;
    unsigned long number = 0;
    if (bpf_probe_read_kernel(&number, sizeof(number), &inode->i_ino)) return 0;
    return number;
}

int syscall__connect(struct pt_regs *ctx, int fd) {
    if (is_sensor()) return 0;
    u64 thread = bpf_get_current_pid_tgid();
    struct endpoint peer = {.fd = fd, .socket_inode = get_socket_inode(fd)};
    endpoints.update(&thread, &peer);
    return 0;
}

// At TCP connect entry the requested peer is in the sockaddr argument.
// The destination fields on struct sock have not been populated yet.
int trace_tcp4(struct pt_regs *ctx, void *sk, struct sockaddr_in *address, int length) {
    u64 thread = bpf_get_current_pid_tgid();
    struct endpoint *peer = endpoints.lookup(&thread);
    if (!peer || length < (int)sizeof(struct sockaddr_in)) return 0;
    struct sockaddr_in remote = {};
    if (bpf_probe_read_kernel(&remote, sizeof(remote), address) || remote.sin_family != AF_INET)
        return 0;
    // IPv4-mapped IPv6 invokes this hook after the IPv6 hook.
    if (peer->family) return 0;
    __builtin_memcpy(peer->address, &remote.sin_addr, sizeof(remote.sin_addr));
    peer->port = remote.sin_port;
    peer->family = AF_INET;
    return 0;
}

int trace_tcp6(struct pt_regs *ctx, void *sk, struct sockaddr_in6 *address, int length) {
    u64 thread = bpf_get_current_pid_tgid();
    struct endpoint *peer = endpoints.lookup(&thread);
    // sin6_scope_id may be absent in the original sockaddr.
    if (!peer || length < (int)offsetof(struct sockaddr_in6, sin6_scope_id)) return 0;
    struct sockaddr_in6 remote = {};
    if (bpf_probe_read_kernel(&remote, offsetof(struct sockaddr_in6, sin6_scope_id), address) ||
        remote.sin6_family != AF_INET6) return 0;
    __builtin_memcpy(peer->address, &remote.sin6_addr, sizeof(remote.sin6_addr));
    peer->port = remote.sin6_port;
    peer->family = AF_INET6;
    return 0;
}

int connect_return(struct pt_regs *ctx) {
    u64 thread = bpf_get_current_pid_tgid();
    struct endpoint *peer = endpoints.lookup(&thread);
    if (!peer) return 0;
    if (peer->family) {
        struct data_t data = {};
        identify(&data, CONNECT);
        data.arg1 = peer->fd;
        data.arg2 = peer->port;
        data.family = peer->family;
        __builtin_memcpy(data.address, peer->address, sizeof(data.address));
        data.result = PT_REGS_RC(ctx);
        if (peer->socket_inode && get_socket_inode(peer->fd) == peer->socket_inode)
            data.socket_inode = peer->socket_inode;
        events.perf_submit(ctx, &data, sizeof(data));
    }
    endpoints.delete(&thread);
    return 0;
}

static __always_inline int track_dup(u32 oldfd, u32 newfd) {
    if (is_sensor()) return 0;
    u64 thread = bpf_get_current_pid_tgid();
    if (newfd > 2 || oldfd == newfd) {
        redirections.delete(&thread);
        return 0;
    }
    struct redirection fds = {oldfd, newfd, get_socket_inode(oldfd)};
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
    if ((long)PT_REGS_RC(ctx) >= 0 && (u32)PT_REGS_RC(ctx) == fds->newfd) {
        struct data_t data = {};
        identify(&data, DUP2);
        data.arg1 = fds->oldfd;
        data.arg2 = fds->newfd;
        if (fds->socket_inode && get_socket_inode(fds->newfd) == fds->socket_inode)
            data.socket_inode = fds->socket_inode;
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
