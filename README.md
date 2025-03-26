## Getting Started with this repo
```
#python deps
python3 -m venv venv
#activate the venv
source venv/bin/activate
pip3 install -r requirements.txt

#Clang deps 
sudo apt-get install bpfcc-tools libbpfcc-dev
```

Run the below command if and only if there is some error related to clang, make or some other ebpf req.
```
sudo apt update
sudo apt install clang llvm libelf-dev libbpf-dev gcc make
```

Here are some commands to test different aspects of your eBPF program:

### 1. Test Basic Clone Events
```bash
# Start a new process
sleep 1 &
```
**Expected Output:**
```
Process sleep (PID: XXXX, PPID: YYYY) called sys_clone
```

### 2. Test File Open Events
```bash
# Open a file
cat /etc/passwd

# List directory (will trigger multiple opens)
ls -l /proc/self/fd
```
**Expected Output:**
```
[timestamp] Process cat (PID: XXXX) opened /etc/passwd
[timestamp] Process ls (PID: XXXX) opened /proc/self/fd
```

### 3. Test Anomaly Detection (Rapid File Opens)
```bash
# Rapid file opens (run in separate terminal)
for i in {1..150}; do
  cat /proc/stat > /dev/null
done
```
**Expected Output:**
```
ANOMALY DETECTED: PID XXXX (cat) opened 100+ files in time window!
```

### 4. Verify Filtering
```bash
# Try to monitor systemd (blocked by filter)
systemctl status

# Check PID 1 (should be filtered out)
ls -l /proc/1/exe
```
**Expected Verification:**
- No output should appear for these commands

### 5. Check Prometheus Metrics
```bash
curl http://localhost:3000
```
**Expected Metrics:**
```
# HELP sys_clone_calls_total Number of sys_clone calls
# TYPE sys_clone_calls_total counter
sys_clone_calls_total 3

# HELP sys_openat_calls_total Number of sys_openat calls 
# TYPE sys_openat_calls_total counter
sys_openat_calls_total 27

# HELP open_anomalies_total Open rate anomalies detected
# TYPE open_anomalies_total counter
open_anomalies_total 1
```

### 6. Stress Test (Optional)
```bash
# Generate many clone events
parallel -j 20 sleep 0.1 ::: {1..100}

# Generate many open events
find /usr/include/ -type f -exec cat {} + > /dev/null
```

### Verification Tips:
1. Events should appear in real-time in the console
2. Filtered events (PID 1/systemd) should never appear
3. Anomalies only trigger when threshold is crossed
4. Metrics should increment with each event
5. No program crashes during high activity

