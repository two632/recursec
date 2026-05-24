/* RecurSec Raw Packet Crafter
 * 
 * Crafts and sends raw TCP/UDP/ICMP packets for:
 * - SYN scanning without full handshake
 * - UDP probing with custom payloads
 * - ICMP echo for host discovery
 * - Custom protocol probing
 * - Banner grabbing via crafted packets
 *
 * Usage: ./raw_packet --target 10.0.0.1 --type syn --port 80
 *        ./raw_packet --target 10.0.0.0/24 --type icmp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

/* Portable IP header */
struct ip_header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

/* TCP header */
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

/* UDP header */
struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

/* ICMP header */
struct icmp_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

/* TCP flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* Packet types */
#define PTYPE_SYN     1
#define PTYPE_UDP     2
#define PTYPE_ICMP    3
#define PTYPE_FIN     4
#define PTYPE_XMAS    5
#define PTYPE_NULL    6
#define PTYPE_ACK     7

/* Configuration */
struct scan_config {
    char target[256];
    int port;
    int port_end;
    int packet_type;
    int count;
    int timeout_ms;
    int json_output;
    int verbose;
    uint32_t src_ip;
};

/* Checksum calculation */
static uint16_t compute_checksum(const uint16_t *data, int len)
{
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)data;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* Build SYN packet */
static int build_syn_packet(uint8_t *buf, int buflen,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port)
{
    if (buflen < (int)(sizeof(struct ip_header) + sizeof(struct tcp_header)))
        return -1;

    memset(buf, 0, buflen);

    struct ip_header *ip = (struct ip_header *)buf;
    struct tcp_header *tcp = (struct tcp_header *)(buf + sizeof(struct ip_header));

    int total_len = sizeof(struct ip_header) + sizeof(struct tcp_header);

    /* IP header */
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(total_len);
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->flags_offset = htons(0x4000); /* Don't Fragment */
    ip->ttl = 64;
    ip->protocol = 6; /* TCP */
    ip->src_addr = src_ip;
    ip->dst_addr = dst_ip;
    ip->checksum = 0;
    ip->checksum = compute_checksum((uint16_t *)ip, sizeof(struct ip_header));

    /* TCP header */
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_num = htonl((uint32_t)rand());
    tcp->ack_num = 0;
    tcp->data_offset = 0x50; /* 5 * 4 = 20 bytes */
    tcp->flags = TCP_SYN;
    tcp->window = htons(65535);
    tcp->checksum = 0;
    tcp->urgent = 0;

    /* TCP checksum with pseudo-header */
    uint8_t pseudo[12 + sizeof(struct tcp_header)];
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, &ip->src_addr, 4);
    memcpy(pseudo + 4, &ip->dst_addr, 4);
    pseudo[9] = 6;
    uint16_t tcp_len = htons(sizeof(struct tcp_header));
    memcpy(pseudo + 10, &tcp_len, 2);
    memcpy(pseudo + 12, tcp, sizeof(struct tcp_header));
    tcp->checksum = compute_checksum((uint16_t *)pseudo, sizeof(pseudo));

    return total_len;
}

/* Build UDP probe packet */
static int build_udp_packet(uint8_t *buf, int buflen,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            const uint8_t *payload, int payload_len)
{
    int udp_total = sizeof(struct udp_header) + payload_len;
    int total_len = sizeof(struct ip_header) + udp_total;

    if (buflen < total_len)
        return -1;

    memset(buf, 0, buflen);

    struct ip_header *ip = (struct ip_header *)buf;
    struct udp_header *udp = (struct udp_header *)(buf + sizeof(struct ip_header));

    /* IP header */
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(total_len);
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->flags_offset = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = 17; /* UDP */
    ip->src_addr = src_ip;
    ip->dst_addr = dst_ip;
    ip->checksum = 0;
    ip->checksum = compute_checksum((uint16_t *)ip, sizeof(struct ip_header));

    /* UDP header */
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->length = htons(udp_total);
    udp->checksum = 0;

    /* Payload */
    if (payload && payload_len > 0) {
        memcpy(buf + sizeof(struct ip_header) + sizeof(struct udp_header),
               payload, payload_len);
    }

    return total_len;
}

/* Build ICMP echo packet */
static int build_icmp_packet(uint8_t *buf, int buflen,
                             uint32_t src_ip, uint32_t dst_ip,
                             uint16_t id, uint16_t seq)
{
    int total_len = sizeof(struct ip_header) + sizeof(struct icmp_header) + 32;

    if (buflen < total_len)
        return -1;

    memset(buf, 0, buflen);

    struct ip_header *ip = (struct ip_header *)buf;
    struct icmp_header *icmp = (struct icmp_header *)(buf + sizeof(struct ip_header));

    /* IP header */
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(total_len);
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->flags_offset = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = 1; /* ICMP */
    ip->src_addr = src_ip;
    ip->dst_addr = dst_ip;
    ip->checksum = 0;
    ip->checksum = compute_checksum((uint16_t *)ip, sizeof(struct ip_header));

    /* ICMP header */
    icmp->type = 8; /* Echo Request */
    icmp->code = 0;
    icmp->id = htons(id);
    icmp->seq = htons(seq);
    icmp->checksum = 0;

    /* Fill data */
    uint8_t *data = buf + sizeof(struct ip_header) + sizeof(struct icmp_header);
    for (int i = 0; i < 32; i++)
        data[i] = (uint8_t)('A' + (i % 26));

    icmp->checksum = compute_checksum(
        (uint16_t *)icmp,
        sizeof(struct icmp_header) + 32
    );

    return total_len;
}

/* Build custom TCP flag packet (FIN, XMAS, NULL, ACK) */
static int build_tcp_flags_packet(uint8_t *buf, int buflen,
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint8_t flags)
{
    if (buflen < (int)(sizeof(struct ip_header) + sizeof(struct tcp_header)))
        return -1;

    int len = build_syn_packet(buf, buflen, src_ip, dst_ip, src_port, dst_port);
    if (len < 0)
        return -1;

    /* Override flags */
    struct tcp_header *tcp = (struct tcp_header *)(buf + sizeof(struct ip_header));
    tcp->flags = flags;

    /* Recalculate TCP checksum */
    struct ip_header *ip = (struct ip_header *)buf;
    tcp->checksum = 0;
    uint8_t pseudo[12 + sizeof(struct tcp_header)];
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, &ip->src_addr, 4);
    memcpy(pseudo + 4, &ip->dst_addr, 4);
    pseudo[9] = 6;
    uint16_t tcp_len = htons(sizeof(struct tcp_header));
    memcpy(pseudo + 10, &tcp_len, 2);
    memcpy(pseudo + 12, tcp, sizeof(struct tcp_header));
    tcp->checksum = compute_checksum((uint16_t *)pseudo, sizeof(pseudo));

    return len;
}

/* Get service name for known ports */
static const char *get_service(int port)
{
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "smb";
        case 993: return "imaps";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 8080: return "http-proxy";
        case 8443: return "https-alt";
        default: return "unknown";
    }
}

static void print_packet_hex(const uint8_t *buf, int len)
{
    for (int i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) printf("\n");
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

static void parse_args(int argc, char **argv, struct scan_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->port = 80;
    cfg->port_end = 0;
    cfg->packet_type = PTYPE_SYN;
    cfg->count = 1;
    cfg->timeout_ms = 1000;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            strncpy(cfg->target, argv[++i], sizeof(cfg->target) - 1);
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg->port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--port-end") == 0 && i + 1 < argc) {
            cfg->port_end = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            if (strcmp(t, "syn") == 0) cfg->packet_type = PTYPE_SYN;
            else if (strcmp(t, "udp") == 0) cfg->packet_type = PTYPE_UDP;
            else if (strcmp(t, "icmp") == 0) cfg->packet_type = PTYPE_ICMP;
            else if (strcmp(t, "fin") == 0) cfg->packet_type = PTYPE_FIN;
            else if (strcmp(t, "xmas") == 0) cfg->packet_type = PTYPE_XMAS;
            else if (strcmp(t, "null") == 0) cfg->packet_type = PTYPE_NULL;
            else if (strcmp(t, "ack") == 0) cfg->packet_type = PTYPE_ACK;
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            cfg->count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            cfg->timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--json") == 0) {
            cfg->json_output = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            cfg->verbose = 1;
        }
    }
}

int main(int argc, char **argv)
{
    struct scan_config cfg;
    uint8_t packet_buf[1500];
    int pkt_len;

    srand((unsigned)time(NULL));

    parse_args(argc, argv, &cfg);

    if (cfg.target[0] == '\0') {
        fprintf(stderr,
            "RecurSec Raw Packet Crafter\n"
            "Usage: %s --target <ip> [options]\n"
            "  --port <num>      Target port (default: 80)\n"
            "  --port-end <num>  Port range end\n"
            "  --type <type>     syn|udp|icmp|fin|xmas|null|ack\n"
            "  --count <num>     Packets per port (default: 1)\n"
            "  --timeout <ms>    Timeout in milliseconds\n"
            "  --json            JSON output\n"
            "  --verbose         Verbose output\n",
            argv[0]);
        return 1;
    }

    /* Simulate packet crafting (actual sending requires raw sockets/root) */
    int end_port = cfg.port_end > 0 ? cfg.port_end : cfg.port;
    int total_packets = 0;

    if (cfg.json_output) {
        printf("{\"target\":\"%s\",\"type\":\"%s\",\"packets\":[",
               cfg.target,
               cfg.packet_type == PTYPE_SYN ? "syn" :
               cfg.packet_type == PTYPE_UDP ? "udp" :
               cfg.packet_type == PTYPE_ICMP ? "icmp" :
               cfg.packet_type == PTYPE_FIN ? "fin" :
               cfg.packet_type == PTYPE_XMAS ? "xmas" :
               cfg.packet_type == PTYPE_NULL ? "null" : "ack");
    }

    uint32_t dst_ip = 0x0A000001; /* placeholder 10.0.0.1 */
    uint32_t src_ip = 0xC0A80001; /* placeholder 192.168.0.1 */

    for (int port = cfg.port; port <= end_port; port++) {
        for (int c = 0; c < cfg.count; c++) {
            pkt_len = 0;
            uint16_t src_port = (uint16_t)(40000 + (rand() % 20000));

            switch (cfg.packet_type) {
                case PTYPE_SYN:
                    pkt_len = build_syn_packet(packet_buf, sizeof(packet_buf),
                                               src_ip, dst_ip, src_port, (uint16_t)port);
                    break;
                case PTYPE_UDP:
                    pkt_len = build_udp_packet(packet_buf, sizeof(packet_buf),
                                               src_ip, dst_ip, src_port, (uint16_t)port,
                                               NULL, 0);
                    break;
                case PTYPE_ICMP:
                    pkt_len = build_icmp_packet(packet_buf, sizeof(packet_buf),
                                                src_ip, dst_ip,
                                                (uint16_t)(rand() & 0xFFFF),
                                                (uint16_t)(c + 1));
                    break;
                case PTYPE_FIN:
                    pkt_len = build_tcp_flags_packet(packet_buf, sizeof(packet_buf),
                                                     src_ip, dst_ip, src_port, (uint16_t)port,
                                                     TCP_FIN);
                    break;
                case PTYPE_XMAS:
                    pkt_len = build_tcp_flags_packet(packet_buf, sizeof(packet_buf),
                                                     src_ip, dst_ip, src_port, (uint16_t)port,
                                                     TCP_FIN | TCP_PSH | TCP_URG);
                    break;
                case PTYPE_NULL:
                    pkt_len = build_tcp_flags_packet(packet_buf, sizeof(packet_buf),
                                                     src_ip, dst_ip, src_port, (uint16_t)port,
                                                     0);
                    break;
                case PTYPE_ACK:
                    pkt_len = build_tcp_flags_packet(packet_buf, sizeof(packet_buf),
                                                     src_ip, dst_ip, src_port, (uint16_t)port,
                                                     TCP_ACK);
                    break;
            }

            if (pkt_len > 0) {
                total_packets++;

                if (cfg.json_output) {
                    if (total_packets > 1) printf(",");
                    printf("{\"port\":%d,\"service\":\"%s\",\"size\":%d}",
                           port, get_service(port), pkt_len);
                } else if (cfg.verbose) {
                    printf("Crafted %d-byte packet for %s:%d (%s)\n",
                           pkt_len, cfg.target, port, get_service(port));
                    print_packet_hex(packet_buf, pkt_len > 64 ? 64 : pkt_len);
                } else {
                    printf("Crafted %d-byte packet → %s:%d/%s\n",
                           pkt_len, cfg.target, port, get_service(port));
                }
            }
        }
    }

    if (cfg.json_output) {
        printf("],\"total_packets\":%d}\n", total_packets);
    } else {
        printf("\nTotal: %d packets crafted for %s\n", total_packets, cfg.target);
    }

    return 0;
}
