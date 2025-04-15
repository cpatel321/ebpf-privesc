from bcc import BPF
import time
import ctypes
from prometheus_client import start_http_server, Counter, Gauge

# Metrics
syn_packets_total = Counter('syn_packets_total', 'Total SYN packets processed')
syn_drops_total = Counter('syn_drops_total', 'Total SYN packets dropped')
active_attackers = Gauge('active_attackers', 'Number of IPs exceeding SYN threshold')
total_syn_rate = Gauge('total_syn_rate', 'Total SYN packets per second')

def ip_to_string(ip):
    return f"{(ip & 0xff)}.{(ip >> 8) & 0xff}.{(ip >> 16) & 0xff}.{(ip >> 24) & 0xff}"

def main():
    # Define BPF program
    bpf_text = """
    #include <uapi/linux/bpf.h>
    #include <linux/in.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>
    #include <linux/tcp.h>

    struct key_t {
        u32 src_ip;
    };

    // Map to track SYN packets per source IP
    BPF_HASH(syn_track, struct key_t, u32, 100000);

    // Map to track total SYN count (for detecting distributed attacks)
    BPF_ARRAY(total_syn, u32, 1);

    // Map to track time window for rate limiting
    BPF_ARRAY(last_update, u64, 1);

    int syn_flood_filter(struct xdp_md *ctx) {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth = data;

        // Check packet size and validate Ethernet header
        if (data + sizeof(*eth) > data_end)
            return XDP_PASS;

        // Check if IP packet
        if (eth->h_proto != htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *ip = data + sizeof(*eth);

        // Check packet size and validate IP header
        if ((void*)ip + sizeof(*ip) > data_end)
            return XDP_PASS;

        // Check if TCP packet
        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        struct tcphdr *tcp = (void*)ip + sizeof(*ip);

        // Check packet size and validate TCP header
        if ((void*)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;

        // Check if SYN packet (SYN=1, ACK=0)
        if (!(tcp->syn && !tcp->ack))
            return XDP_PASS;

        // Get current timestamp
        u64 now = bpf_ktime_get_ns();

        // Get last update time
        int zero = 0;
        u64 *last = last_update.lookup(&zero);
        u64 last_time = 0;
        if (last)
            last_time = *last;

        // Reset counter if more than 1 second has passed
        if (now > last_time + 1000000000) {
            u32 zero_count = 0;
            total_syn.update(&zero, &zero_count);
            last_update.update(&zero, &now);
        }

        // Increment total SYN count
        u32 *total = total_syn.lookup(&zero);
        u32 new_total = 1;
        if (total)
            new_total = *total + 1;
        total_syn.update(&zero, &new_total);

        // Create key with source IP
        struct key_t key = {0};
        key.src_ip = ip->saddr;

        // Increment SYN count for this IP
        u32 *count = syn_track.lookup(&key);
        u32 new_count = 1;
        if (count)
            new_count = *count + 1;

        syn_track.update(&key, &new_count);

        // Drop if per-IP threshold exceeded
        if (new_count > 100) {
            return XDP_DROP;
        }

        // Drop if total SYN rate threshold exceeded (distributed attack)
        if (new_total > 1000) { // 1000 SYN packets per second threshold
            return XDP_DROP;
        }

        return XDP_PASS;
    }
    """

    # Load BPF program
    b = BPF(text=bpf_text)

    # Attach XDP program to interface
    interface = "enp0s3"  # Using the available interface
    fn = b.load_func("syn_flood_filter", BPF.XDP)
    b.attach_xdp(interface, fn)

    syn_track = b.get_table("syn_track")
    total_syn = b.get_table("total_syn")

    print(f"SYN flood protection active on {interface}")
    print("Monitoring for attacks...")
    print("Detecting both single-source and distributed SYN flood attacks")

    try:
        while True:
            attackers = 0
            syn_rate = 0

            # Get total SYN rate
            try:
                syn_rate = total_syn[0].value
                total_syn_rate.set(syn_rate)
            except KeyError:
                pass

            # Print statistics
            print("\n--- SYN Flood Statistics ---")
            print(f"Total SYN packets in last second: {syn_rate}")

            # Check if we're under a distributed attack
            if syn_rate > 1000:
                print(f"⚠️ ALERT: Distributed SYN flood attack detected! ({syn_rate} SYN/sec)")
                syn_drops_total.inc(syn_rate)

            # Check individual attackers
            for k, v in syn_track.items():
                ip = ip_to_string(k.src_ip)
                count = v.value
                if count > 100:  # Threshold
                    attackers += 1
                    print(f"Potential attacker: {ip} - {count} SYN packets")

            active_attackers.set(attackers)
            syn_packets_total.inc(syn_rate)

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nUnloading XDP program...")
        b.remove_xdp(interface)

if __name__ == "__main__":
    start_http_server(3000)
    main()