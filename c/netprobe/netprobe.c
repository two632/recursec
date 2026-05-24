/*
 * RecurSec Network Probe — fast TCP port scanning in C
 *
 * Features:
 * - Non-blocking TCP connect scan
 * - Service banner grabbing
 * - Connection timing for latency profiling
 * - JSON output for agent consumption
 *
 * Usage: ./netprobe --host 10.0.0.1 --ports 1-1024 --timeout 500 --json
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>

#define MAX_BANNER 256
#define DEFAULT_TIMEOUT_MS 1000

typedef struct {
    int port;
    int open;
    char banner[MAX_BANNER];
    double latency_ms;
    char service[64];
} PortResult;

typedef struct {
    char host[256];
    int port_start;
    int port_end;
    int timeout_ms;
    int json_output;
    int banner_grab;
    int verbose;
} ScanConfig;

static const char* get_service_name(int port) {
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 135: return "msrpc";
        case 139: return "netbios";
        case 143: return "imap";
        case 161: return "snmp";
        case 389: return "ldap";
        case 443: return "https";
        case 445: return "smb";
        case 465: return "smtps";
        case 587: return "submission";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 6379: return "redis";
        case 6443: return "k8s-api";
        case 8080: return "http-proxy";
        case 8443: return "https-alt";
        case 9200: return "elasticsearch";
        case 27017: return "mongodb";
        default: return "unknown";
    }
}

static double now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static PortResult scan_tcp_port(const char *host, int port, int timeout_ms, int banner_grab) {
    PortResult result;
    memset(&result, 0, sizeof(result));
    result.port = port;
    strncpy(result.service, get_service_name(port), sizeof(result.service) - 1);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) return result;
        memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return result;

    set_nonblocking(sock);

    double start = now_ms();
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    if (ret == 0) {
        result.open = 1;
        result.latency_ms = now_ms() - start;
    } else if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        ret = poll(&pfd, 1, timeout_ms);
        if (ret > 0 && (pfd.revents & POLLOUT)) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
            if (error == 0) {
                result.open = 1;
                result.latency_ms = now_ms() - start;

                if (banner_grab) {
                    int fl = fcntl(sock, F_GETFL, 0);
                    fcntl(sock, F_SETFL, fl & ~O_NONBLOCK);
                    struct timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 500000;
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    ssize_t n = recv(sock, result.banner, MAX_BANNER - 1, 0);
                    if (n > 0) {
                        result.banner[n] = '\0';
                        for (int i = 0; i < n; i++) {
                            if (result.banner[i] < 32 && result.banner[i] != '\0')
                                result.banner[i] = '.';
                        }
                    }
                }
            }
        }
    }

    close(sock);
    return result;
}

static void output_json(PortResult *results, int count, const char *host) {
    printf("{\"host\":\"%s\",\"open_ports\":[", host);
    int first = 1;
    for (int i = 0; i < count; i++) {
        if (results[i].open) {
            if (!first) printf(",");
            printf("{\"port\":%d,\"service\":\"%s\",\"latency_ms\":%.1f",
                   results[i].port, results[i].service, results[i].latency_ms);
            if (results[i].banner[0]) {
                printf(",\"banner\":\"");
                for (int j = 0; results[i].banner[j]; j++) {
                    char c = results[i].banner[j];
                    if (c == '"') printf("\\\"");
                    else if (c == '\\') printf("\\\\");
                    else if (c == '\n') printf("\\n");
                    else if (c == '\r') printf("\\r");
                    else putchar(c);
                }
                printf("\"");
            }
            printf("}");
            first = 0;
        }
    }
    printf("],\"total_scanned\":%d}\n", count);
}

static void output_text(PortResult *results, int count, const char *host) {
    printf("Scan results for %s:\n", host);
    printf("%-8s %-6s %-15s %-12s %s\n", "PORT", "STATE", "SERVICE", "LATENCY", "BANNER");
    int open_count = 0;
    for (int i = 0; i < count; i++) {
        if (results[i].open) {
            printf("%-8d %-6s %-15s %-12.1fms %s\n",
                   results[i].port, "open", results[i].service,
                   results[i].latency_ms, results[i].banner);
            open_count++;
        }
    }
    printf("\n%d ports open out of %d scanned\n", open_count, count);
}

int main(int argc, char *argv[]) {
    ScanConfig config;
    memset(&config, 0, sizeof(config));
    config.port_start = 1;
    config.port_end = 1024;
    config.timeout_ms = DEFAULT_TIMEOUT_MS;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            strncpy(config.host, argv[++i], sizeof(config.host) - 1);
        } else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
            sscanf(argv[++i], "%d-%d", &config.port_start, &config.port_end);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            config.timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--json") == 0) {
            config.json_output = 1;
        } else if (strcmp(argv[i], "--banner") == 0) {
            config.banner_grab = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            config.verbose = 1;
        }
    }

    if (!config.host[0]) {
        fprintf(stderr, "Usage: %s --host <target> [--ports 1-1024] [--timeout 1000] [--json] [--banner]\n", argv[0]);
        return 1;
    }

    if (config.port_start < 1) config.port_start = 1;
    if (config.port_end > 65535) config.port_end = 65535;

    int port_count = config.port_end - config.port_start + 1;
    PortResult *results = calloc((size_t)port_count, sizeof(PortResult));
    if (!results) { fprintf(stderr, "OOM\n"); return 1; }

    if (config.verbose)
        fprintf(stderr, "Scanning %s ports %d-%d\n", config.host, config.port_start, config.port_end);

    double scan_start = now_ms();
    for (int i = 0; i < port_count; i++) {
        results[i] = scan_tcp_port(config.host, config.port_start + i, config.timeout_ms, config.banner_grab);
    }
    double elapsed = now_ms() - scan_start;

    if (config.json_output)
        output_json(results, port_count, config.host);
    else {
        output_text(results, port_count, config.host);
        printf("Scan completed in %.1fms\n", elapsed);
    }

    free(results);
    return 0;
}
