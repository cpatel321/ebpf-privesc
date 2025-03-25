#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <bcc/proto.h>

// Key structure for command filtering
struct comm_key {
    char comm[TASK_COMM_LEN];
};

struct clone_data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

struct open_data_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
};

struct config {
    u64 window_ns;
    u64 threshold;
};

struct anomaly_data_t {
    u32 pid;
    u64 count;
    char comm[TASK_COMM_LEN];
};

struct open_count_val {
    u64 count;
    u64 window_start;
};

BPF_PERF_OUTPUT(clone_events);
BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(anomaly_events);

BPF_HASH(blocked_pids, u32, u8);
BPF_HASH(blocked_comms, struct comm_key, u8);
BPF_HASH(config_map, u32, struct config);
BPF_HASH(open_counts, u32, struct open_count_val);

int kprobe__sys_clone(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    
    // Check blocked PIDs
    u8 *is_blocked = blocked_pids.lookup(&pid);
    if (is_blocked) return 0;
    
    // Check blocked comms
    struct comm_key key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    u8 *comm_blocked = blocked_comms.lookup(&key);
    if (comm_blocked) return 0;

    struct clone_data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.pid = pid;
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    clone_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    u32 pid = bpf_get_current_pid_tgid();
    
    // Check blocked PIDs
    u8 *is_blocked = blocked_pids.lookup(&pid);
    if (is_blocked) return 0;

    // Check blocked comms
    struct comm_key key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    u8 *comm_blocked = blocked_comms.lookup(&key);
    if (comm_blocked) return 0;

    struct open_data_t data = {};
    data.pid = pid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    open_events.perf_submit(ctx, &data, sizeof(data));

    u32 zero = 0;
    struct config *cfg = config_map.lookup(&zero);
    u64 window_ns = cfg ? cfg->window_ns : 1000000000;
    u64 threshold = cfg ? cfg->threshold : 100;
    u64 now = bpf_ktime_get_ns();

    struct open_count_val *count_val;
    struct open_count_val new_val = {.count = 1, .window_start = now};
    
    count_val = open_counts.lookup(&pid);
    if (count_val) {
        if (now < count_val->window_start + window_ns) {
            count_val->count++;
        } else {
            new_val.count = 1;
            open_counts.update(&pid, &new_val);
        }
    } else {
        open_counts.update(&pid, &new_val);
    }

    if (count_val && count_val->count > threshold) {
        struct anomaly_data_t anomaly = {};
        anomaly.pid = pid;
        anomaly.count = count_val->count;
        bpf_get_current_comm(&anomaly.comm, sizeof(anomaly.comm));
        anomaly_events.perf_submit(ctx, &anomaly, sizeof(anomaly));
    }

    return 0;
}