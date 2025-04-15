from bcc import BPF
import time
import ctypes
from prometheus_client import start_http_server, Counter, Gauge

# Metrics
syn_packets_total = Counter('syn_packets_total', 'Total SYN packets processed')
syn_drops_total = Counter('syn_drops_total', 'Total SYN packets dropped')
active_attackers = Gauge('active_attackers', 'Number of IPs exceeding SYN threshold')

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

    BPF_HASH(syn_track, struct key_t, u32, 100000);

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

        // Create key with source IP
        struct key_t key = {0};
        key.src_ip = ip->saddr;

        // Increment SYN count for this IP
        u32 *count = syn_track.lookup(&key);
        u32 new_count = 1;
        if (count)
            new_count = *count + 1;

        syn_track.update(&key, &new_count);

        // Drop if threshold exceeded
        if (new_count > 100) {
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

    print(f"SYN flood protection active on {interface}")
    print("Monitoring for attacks...")

    try:
        while True:
            attackers = 0

            # Print statistics
            print("\n--- SYN Flood Statistics ---")
            for k, v in syn_track.items():
                ip = ip_to_string(k.src_ip)
                count = v.value
                if count > 100:  # Threshold
                    attackers += 1
                    print(f"Potential attacker: {ip} - {count} SYN packets")

            active_attackers.set(attackers)
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nUnloading XDP program...")
        b.remove_xdp(interface)

if __name__ == "__main__":
    start_http_server(3000)
    main()