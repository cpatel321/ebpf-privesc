#!/usr/bin/env python3

from bcc import BPF
from pathlib import Path
from prometheus_client import start_http_server, Counter
import ctypes as ct

# Initialize Prometheus metrics
sys_clone_counter = Counter('sys_clone_calls_total', 'Number of sys_clone calls')
sys_openat_counter = Counter('sys_openat_calls_total', 'Number of sys_openat calls')
anomaly_counter = Counter('open_anomalies_total', 'Open rate anomalies detected')

start_http_server(3000)

# Define C structures for map access
class comm_key(ct.Structure):
    _fields_ = [("comm", ct.c_char * 16)]  # TASK_COMM_LEN = 16

class Config(ct.Structure):
    _fields_ = [("window_ns", ct.c_ulonglong),
                ("threshold", ct.c_ulonglong)]

def process_clone_event(cpu, data, size):
    event = bpf["clone_events"].event(data)
    print(f"Process {event.comm.decode()} (PID: {event.pid}, PPID: {event.ppid}) called sys_clone")
    sys_clone_counter.inc()

def process_open_event(cpu, data, size):
    event = bpf["open_events"].event(data)
    print(f"[{event.timestamp / 1e9:.6f}] Process {event.comm.decode()} (PID: {event.pid}) opened {event.filename.decode()}")
    sys_openat_counter.inc()

def process_anomaly_event(cpu, data, size):
    event = bpf["anomaly_events"].event(data)
    print(f"ANOMALY DETECTED: PID {event.pid} ({event.comm.decode()}) opened {event.count} files in time window!")
    anomaly_counter.inc()

# Load eBPF program
bpf_source = Path('ebpf-probe.c').read_text()
bpf = BPF(text=bpf_source)

# Configure filtering
# Block PID 1 (init)
blocked_pids = bpf["blocked_pids"]
blocked_pids[ct.c_uint32(1)] = ct.c_uint8(1)

# Block comm 'systemd'
blocked_comms = bpf["blocked_comms"]
key = comm_key()
key.comm = b'systemd'.ljust(16, b'\x00')
blocked_comms[key] = ct.c_uint8(1)

# Configure anomaly detection
config_map = bpf["config_map"]
cfg = Config()
cfg.window_ns = int(1e9)  # 1 second window
cfg.threshold = 100        # 100 file opens
config_map[ct.c_uint32(0)] = cfg

# Set up perf buffers
bpf["clone_events"].open_perf_buffer(process_clone_event)
bpf["open_events"].open_perf_buffer(process_open_event)
bpf["anomaly_events"].open_perf_buffer(process_anomaly_event)

print("Monitoring sys_clone and file open events with filtering and anomaly detection...")

try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nMonitoring stopped")