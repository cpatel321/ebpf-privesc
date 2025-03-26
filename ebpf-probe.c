#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <bcc/proto.h>

// Common data structure for process filtering
#define SUDO_COMM "sudo"
#define SUDO_COMM_LEN sizeof(SUDO_COMM)

struct clone_data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

struct open_data_t {
    u32 pid;
    u64 timestamp;
    long ret;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
};

BPF_PERF_OUTPUT(clone_events);
BPF_PERF_OUTPUT(open_events);
BPF_HASH(open_temp, u32, struct open_data_t);

// Check if process name matches sudo
static inline int is_sudo_process(const char *comm) {
    return __builtin_memcmp(comm, SUDO_COMM, SUDO_COMM_LEN-1) == 0;
}

int kprobe__sys_clone(void *ctx) {
    struct clone_data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (!is_sudo_process(data.comm)) return 0;
    
    data.pid = bpf_get_current_pid_tgid();
    data.ppid = task->real_parent->tgid;
    
    clone_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    u32 pid = bpf_get_current_pid_tgid();
    struct open_data_t data = {};
    
    // Parent check
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = task->real_parent;
    char parent_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel_str(parent_comm, sizeof(parent_comm), parent->comm);
    if (!is_sudo_process(parent_comm)) return 0;

    // Store temporary data
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), filename);
    open_temp.update(&pid, &data);
    
    return 0;
}

int kretprobe__do_sys_openat2(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct open_data_t *data = open_temp.lookup(&pid);
    if (!data) return 0;

    data->ret = PT_REGS_RC(ctx);
    open_events.perf_submit(ctx, data, sizeof(*data));
    open_temp.delete(&pid);
    return 0;
}
