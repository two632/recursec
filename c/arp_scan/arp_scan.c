/*
 * RecurSec ARP Scanner — Fast local network host discovery via ARP.
 *
 * Sends ARP requests to discover live hosts on the local network.
 * Uses raw sockets for direct ARP packet construction.
 *
 * Build: gcc -O2 -o arp_scan arp_scan.c
 * Usage: sudo ./arp_scan <interface> <network_cidr>
 * Example: sudo ./arp_scan eth0 192.168.1.0/24
 *
 * NOTE: Requires root/sudo for raw socket access.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#ifdef __linux__
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#endif

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_HOSTS 65536

typedef struct {
    char ip[16];
    char mac[18];
    double response_time_ms;
} HostEntry;

typedef struct {
    HostEntry hosts[MAX_HOSTS];
    int count;
    double scan_time;
    char network[32];
    char interface_name[32];
} ScanResult;

/* Parse CIDR into base IP and mask */
static int parse_cidr(const char *cidr, uint32_t *base_ip, uint32_t *mask, int *prefix_len) {
    char ip_str[32];
    int prefix = 24;

    strncpy(ip_str, cidr, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    char *slash = strchr(ip_str, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;
    }

    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) return -1;

    *base_ip = ntohl(addr.s_addr);
    *mask = prefix == 0 ? 0 : (~0U << (32 - prefix));
    *base_ip &= *mask;
    *prefix_len = prefix;

    return 0;
}

static void ip_to_str(uint32_t ip, char *buf, size_t buf_size) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, buf_size);
}

static int get_interface_info(const char *ifname, int sock, unsigned char *mac, uint32_t *ip) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    /* Get MAC address */
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    /* Get IP address */
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = ntohl(sin->sin_addr.s_addr);

    return 0;
}

#ifdef __linux__
static int send_arp_request(int sock, int ifindex, unsigned char *src_mac,
                            uint32_t src_ip, uint32_t dst_ip) {
    unsigned char packet[42];
    memset(packet, 0, sizeof(packet));

    /* Ethernet header */
    memset(packet, 0xff, 6);              /* Destination: broadcast */
    memcpy(packet + 6, src_mac, 6);       /* Source MAC */
    packet[12] = 0x08; packet[13] = 0x06; /* EtherType: ARP */

    /* ARP header */
    packet[14] = 0x00; packet[15] = 0x01; /* Hardware type: Ethernet */
    packet[16] = 0x08; packet[17] = 0x00; /* Protocol type: IPv4 */
    packet[18] = 6;                        /* Hardware size */
    packet[19] = 4;                        /* Protocol size */
    packet[20] = 0x00; packet[21] = 0x01; /* Opcode: ARP Request */

    /* Sender MAC + IP */
    memcpy(packet + 22, src_mac, 6);
    uint32_t src_ip_n = htonl(src_ip);
    memcpy(packet + 28, &src_ip_n, 4);

    /* Target MAC (zeros) + IP */
    memset(packet + 32, 0, 6);
    uint32_t dst_ip_n = htonl(dst_ip);
    memcpy(packet + 38, &dst_ip_n, 4);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xff, 6);

    return sendto(sock, packet, 42, 0, (struct sockaddr *)&addr, sizeof(addr));
}
#endif

static void output_json(const ScanResult *result) {
    printf("{\n");
    printf("  \"network\": \"%s\",\n", result->network);
    printf("  \"interface\": \"%s\",\n", result->interface_name);
    printf("  \"hosts_found\": %d,\n", result->count);
    printf("  \"scan_time_s\": %.3f,\n", result->scan_time);
    printf("  \"hosts\": [\n");

    for (int i = 0; i < result->count; i++) {
        printf("    {\"ip\": \"%s\", \"mac\": \"%s\", \"response_ms\": %.2f}%s\n",
               result->hosts[i].ip,
               result->hosts[i].mac,
               result->hosts[i].response_time_ms,
               (i < result->count - 1) ? "," : "");
    }

    printf("  ]\n");
    printf("}\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "RecurSec ARP Scanner — Fast local network discovery\n\n");
        fprintf(stderr, "Usage: %s <interface> <network/cidr> [json|text]\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 192.168.1.0/24\n", argv[0]);
        fprintf(stderr, "\nRequires root privileges for raw socket access.\n");
        return 1;
    }

    const char *ifname = argv[1];
    const char *cidr = argv[2];
    int json_output = 1;

    if (argc > 3 && strcmp(argv[3], "text") == 0) {
        json_output = 0;
    }

    uint32_t base_ip, mask;
    int prefix_len;
    if (parse_cidr(cidr, &base_ip, &mask, &prefix_len) < 0) {
        fprintf(stderr, "Invalid CIDR: %s\n", cidr);
        return 1;
    }

    uint32_t num_hosts = (1 << (32 - prefix_len)) - 2;  /* Exclude network and broadcast */
    if (num_hosts > MAX_HOSTS) {
        fprintf(stderr, "Network too large (max /%d)\n", 16);
        return 1;
    }

#ifdef __linux__
    /* Create raw socket */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket (need root?)");
        return 1;
    }

    /* Get interface info */
    unsigned char src_mac[6];
    uint32_t src_ip;
    if (get_interface_info(ifname, sock, src_mac, &src_ip) < 0) {
        close(sock);
        return 1;
    }

    /* Get interface index */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return 1;
    }
    int ifindex = ifr.ifr_ifindex;

    ScanResult result;
    memset(&result, 0, sizeof(result));
    strncpy(result.network, cidr, sizeof(result.network) - 1);
    strncpy(result.interface_name, ifname, sizeof(result.interface_name) - 1);

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    if (!json_output) {
        printf("Scanning %s via %s (%d hosts)...\n", cidr, ifname, num_hosts);
    }

    /* Send ARP requests to all hosts */
    for (uint32_t i = 1; i <= num_hosts; i++) {
        uint32_t target = base_ip + i;
        send_arp_request(sock, ifindex, src_mac, src_ip, target);
        usleep(1000);  /* 1ms between requests */
    }

    /* Receive ARP replies */
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char buf[256];
    while (1) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n < 42) break;

        /* Check if ARP reply */
        if (buf[12] == 0x08 && buf[13] == 0x06 &&    /* EtherType ARP */
            buf[20] == 0x00 && buf[21] == 0x02) {     /* ARP Reply */

            uint32_t sender_ip;
            memcpy(&sender_ip, buf + 28, 4);
            sender_ip = ntohl(sender_ip);

            /* Check if in our target range */
            if ((sender_ip & mask) == base_ip && result.count < MAX_HOSTS) {
                HostEntry *entry = &result.hosts[result.count];
                ip_to_str(sender_ip, entry->ip, sizeof(entry->ip));
                snprintf(entry->mac, sizeof(entry->mac),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
                entry->response_time_ms = 0;  /* Could track per-host timing */
                result.count++;
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    result.scan_time = (ts_end.tv_sec - ts_start.tv_sec) +
                       (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    close(sock);

    if (json_output) {
        output_json(&result);
    } else {
        printf("\nFound %d hosts in %.2fs:\n\n", result.count, result.scan_time);
        for (int i = 0; i < result.count; i++) {
            printf("  %-15s  %s\n", result.hosts[i].ip, result.hosts[i].mac);
        }
    }

#else
    fprintf(stderr, "ARP scanning requires Linux raw sockets.\n");
    return 1;
#endif

    return 0;
}
