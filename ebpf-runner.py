from collections import defaultdict
from datetime import datetime
import time
from bcc import BPF
from pathlib import Path
from prometheus_client import start_http_server, Counter, Gauge

# Metrics
sys_clone_counter = Counter('sys_clone_calls_total', 'Number of sudo process spawns')
sys_open_counter = Counter('sys_openat_success_total', 'Number of successful sudo file opens')
sys_open_failed = Counter('sys_openat_failed_total', 'Number of failed sudo file opens')
sudo_anomalies = Gauge('sudo_anomalies', 'Detected sudo anomalies')

# Anomaly detection config
FAILURE_THRESHOLD = 3
TIME_WINDOW = 60  # seconds
failed_attempts = defaultdict(lambda: {'count': 0, 'first_ts': 0})

def process_clone_event(cpu, data, size):
    event = bpf["clone_events"].event(data)
    print(f"Sudo process spawned: {event.comm.decode()} (PID: {event.pid})")
    sys_clone_counter.inc()

def process_open_event(cpu, data, size):
    event = bpf["open_events"].event(data)
    timestamp = event.timestamp / 1e9
    
    if event.ret < 0:  # Error case
        sys_open_failed.inc()
        key = (event.pid, event.filename.decode())
        
        # Anomaly detection logic
        now = time.time()
        record = failed_attempts[key]
        
        if now - record['first_ts'] > TIME_WINDOW:
            # Reset counter for new time window
            record.update({'count': 1, 'first_ts': now})
        else:
            record['count'] += 1

        if record['count'] >= FAILURE_THRESHOLD:
            dt = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{dt} ANOMALY: PID {event.pid} failed to open "
                  f"{event.filename.decode()} {record['count']} times!")
            sudo_anomalies.set(1)
            record['count'] = 0  # Reset after alerting
    else:
        sys_open_counter.inc()
        print(f"[{timestamp:.6f}] Sudo child opened: {event.filename.decode()}")

if __name__ == "__main__":
    start_http_server(3000)
    bpf = BPF(text=Path('ebpf-probe.c').read_text())
    bpf["clone_events"].open_perf_buffer(process_clone_event)
    bpf["open_events"].open_perf_buffer(process_open_event)
    
    print("Monitoring sudo-related activity...")
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            break
