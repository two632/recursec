/*
 * RecurSec C Network Probe — Ultra-fast TCP port probe and banner grabber.
 *
 * Designed for maximum performance using non-blocking I/O with select().
 * Can probe thousands of ports simultaneously.
 *
 * Features:
 * - Non-blocking TCP connect with configurable timeout
 * - Batch probing with select() for high concurrency
 * - Banner grabbing on open ports
 * - JSON output for agent consumption
 * - Minimal memory footprint
 *
 * Build: gcc -O2 -o probe probe.c
 * Usage: ./probe <host> <port_start> <port_end> [timeout_ms] [json]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#define MAX_CONCURRENT 1024
#define BANNER_BUF_SIZE 1024
#define MAX_OPEN_PORTS 65536

typedef struct {
    int port;
    char banner[BANNER_BUF_SIZE];
    int banner_len;
    char service[64];
} OpenPort;

typedef struct {
    char host[256];
    char ip[64];
    int port_start;
    int port_end;
    int timeout_ms;
    int json_output;
    int banner_grab;
    int batch_size;
} ProbeConfig;

typedef struct {
    OpenPort ports[MAX_OPEN_PORTS];
    int count;
    int total_scanned;
    double scan_time;
} ProbeResult;

/* Known port → service mapping */
static const struct {
    int port;
    const char *service;
} KNOWN_SERVICES[] = {
    {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"},
    {53, "dns"}, {80, "http"}, {110, "pop3"}, {111, "rpcbind"},
    {135, "msrpc"}, {139, "netbios"}, {143, "imap"}, {161, "snmp"},
    {389, "ldap"}, {443, "https"}, {445, "smb"}, {465, "smtps"},
    {587, "submission"}, {636, "ldaps"}, {993, "imaps"}, {995, "pop3s"},
    {1080, "socks"}, {1433, "mssql"}, {1521, "oracle"}, {1883, "mqtt"},
    {2049, "nfs"}, {2181, "zookeeper"}, {2375, "docker"},
    {3306, "mysql"}, {3389, "rdp"}, {3690, "svn"},
    {4369, "epmd"}, {4443, "https-alt"}, {5000, "upnp"},
    {5432, "postgresql"}, {5672, "amqp"}, {5900, "vnc"},
    {5984, "couchdb"}, {6379, "redis"}, {6443, "kubernetes"},
    {6660, "irc"}, {6667, "irc"}, {7001, "weblogic"},
    {8000, "http-alt"}, {8008, "http-alt"}, {8080, "http-proxy"},
    {8081, "http-alt"}, {8443, "https-alt"}, {8888, "http-alt"},
    {9090, "prometheus"}, {9092, "kafka"}, {9200, "elasticsearch"},
    {9300, "elasticsearch"}, {9418, "git"}, {11211, "memcached"},
    {15672, "rabbitmq-mgmt"}, {27017, "mongodb"}, {27018, "mongodb"},
    {50000, "jenkins"}, {50070, "hadoop"},
    {0, NULL}
};

static const char *lookup_service(int port) {
    for (int i = 0; KNOWN_SERVICES[i].service != NULL; i++) {
        if (KNOWN_SERVICES[i].port == port)
            return KNOWN_SERVICES[i].service;
    }
    return "unknown";
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int resolve_host(const char *host, char *ip_buf, size_t ip_buf_size) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rv = getaddrinfo(host, NULL, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "Error resolving %s: %s\n", host, gai_strerror(rv));
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_buf, ip_buf_size);
    freeaddrinfo(res);
    return 0;
}

/* Probe a batch of ports using non-blocking connect + select */
static void probe_batch(const char *ip, int *ports, int num_ports,
                        int timeout_ms, int banner_grab,
                        ProbeResult *result) {
    int socks[MAX_CONCURRENT];
    int sock_port[MAX_CONCURRENT];
    int active = 0;

    /* Create non-blocking connections */
    for (int i = 0; i < num_ports && i < MAX_CONCURRENT; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        if (set_nonblocking(sock) < 0) {
            close(sock);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        inet_pton(AF_INET, ip, &addr.sin_addr);

        int rv = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (rv == 0) {
            /* Immediate connection (unlikely for non-blocking) */
            OpenPort *op = &result->ports[result->count++];
            op->port = ports[i];
            strncpy(op->service, lookup_service(ports[i]), sizeof(op->service) - 1);
            close(sock);
        } else if (errno == EINPROGRESS) {
            socks[active] = sock;
            sock_port[active] = ports[i];
            active++;
        } else {
            close(sock);
        }
    }

    if (active == 0) return;

    /* Wait for connections with select() */
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set writefds;
    FD_ZERO(&writefds);
    int maxfd = 0;

    for (int i = 0; i < active; i++) {
        FD_SET(socks[i], &writefds);
        if (socks[i] > maxfd) maxfd = socks[i];
    }

    int ready = select(maxfd + 1, NULL, &writefds, NULL, &tv);
    if (ready > 0) {
        for (int i = 0; i < active; i++) {
            if (FD_ISSET(socks[i], &writefds)) {
                int error = 0;
                socklen_t len = sizeof(error);
                getsockopt(socks[i], SOL_SOCKET, SO_ERROR, &error, &len);

                if (error == 0 && result->count < MAX_OPEN_PORTS) {
                    OpenPort *op = &result->ports[result->count];
                    op->port = sock_port[i];
                    strncpy(op->service, lookup_service(sock_port[i]), sizeof(op->service) - 1);
                    op->banner_len = 0;

                    /* Banner grab */
                    if (banner_grab) {
                        /* Send a probe and read response */
                        char probe_data[] = "\r\n";
                        send(socks[i], probe_data, strlen(probe_data), MSG_NOSIGNAL);

                        struct timeval banner_tv;
                        banner_tv.tv_sec = 0;
                        banner_tv.tv_usec = 500000; /* 500ms for banner */

                        fd_set readfds;
                        FD_ZERO(&readfds);
                        FD_SET(socks[i], &readfds);

                        if (select(socks[i] + 1, &readfds, NULL, NULL, &banner_tv) > 0) {
                            int n = recv(socks[i], op->banner, BANNER_BUF_SIZE - 1, 0);
                            if (n > 0) {
                                op->banner[n] = '\0';
                                op->banner_len = n;
                                /* Clean non-printable chars */
                                for (int j = 0; j < n; j++) {
                                    if (op->banner[j] < 32 && op->banner[j] != '\n' && op->banner[j] != '\r')
                                        op->banner[j] = '.';
                                }
                            }
                        }
                    }

                    result->count++;
                }
            }
        }
    }

    /* Cleanup */
    for (int i = 0; i < active; i++) {
        close(socks[i]);
    }
}

static void output_json(const ProbeConfig *config, const ProbeResult *result) {
    printf("{\n");
    printf("  \"host\": \"%s\",\n", config->host);
    printf("  \"ip\": \"%s\",\n", config->ip);
    printf("  \"port_range\": \"%d-%d\",\n", config->port_start, config->port_end);
    printf("  \"total_scanned\": %d,\n", result->total_scanned);
    printf("  \"open_ports\": %d,\n", result->count);
    printf("  \"scan_time_s\": %.3f,\n", result->scan_time);
    printf("  \"ports\": [\n");

    for (int i = 0; i < result->count; i++) {
        const OpenPort *op = &result->ports[i];
        printf("    {\"port\": %d, \"service\": \"%s\"", op->port, op->service);
        if (op->banner_len > 0) {
            /* Escape JSON string */
            printf(", \"banner\": \"");
            for (int j = 0; j < op->banner_len && j < 200; j++) {
                char c = op->banner[j];
                if (c == '"') printf("\\\"");
                else if (c == '\\') printf("\\\\");
                else if (c == '\n') printf("\\n");
                else if (c == '\r') printf("\\r");
                else if (c >= 32) putchar(c);
                else printf(".");
            }
            printf("\"");
        }
        printf("}%s\n", (i < result->count - 1) ? "," : "");
    }

    printf("  ]\n");
    printf("}\n");
}

static void output_text(const ProbeConfig *config, const ProbeResult *result) {
    printf("Probe %s (%s) ports %d-%d\n", config->host, config->ip, config->port_start, config->port_end);
    printf("Found %d open ports (scanned %d in %.3fs)\n\n", result->count, result->total_scanned, result->scan_time);

    for (int i = 0; i < result->count; i++) {
        const OpenPort *op = &result->ports[i];
        printf("  %-6d %-15s", op->port, op->service);
        if (op->banner_len > 0) {
            /* Print first line of banner */
            printf("  ");
            for (int j = 0; j < op->banner_len && j < 80; j++) {
                if (op->banner[j] == '\n' || op->banner[j] == '\r') break;
                putchar(op->banner[j]);
            }
        }
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "RecurSec Probe — Ultra-fast TCP port probe\n\n");
        fprintf(stderr, "Usage: %s <host> <port_start> <port_end> [timeout_ms] [json|text] [banner]\n", argv[0]);
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  %s 192.168.1.1 1 1024\n", argv[0]);
        fprintf(stderr, "  %s example.com 1 65535 2000 json banner\n", argv[0]);
        return 1;
    }

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    ProbeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.host, argv[1], sizeof(config.host) - 1);
    config.port_start = atoi(argv[2]);
    config.port_end = atoi(argv[3]);
    config.timeout_ms = (argc > 4) ? atoi(argv[4]) : 2000;
    config.json_output = 1; /* default JSON */
    config.banner_grab = 0;
    config.batch_size = MAX_CONCURRENT;

    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "text") == 0) config.json_output = 0;
        else if (strcmp(argv[i], "json") == 0) config.json_output = 1;
        else if (strcmp(argv[i], "banner") == 0) config.banner_grab = 1;
    }

    if (config.port_start < 1) config.port_start = 1;
    if (config.port_end > 65535) config.port_end = 65535;
    if (config.port_start > config.port_end) {
        fprintf(stderr, "Error: port_start must be <= port_end\n");
        return 1;
    }

    /* Resolve host */
    if (resolve_host(config.host, config.ip, sizeof(config.ip)) < 0) {
        return 1;
    }

    ProbeResult result;
    memset(&result, 0, sizeof(result));

    struct timeval start, end;
    gettimeofday(&start, NULL);

    /* Scan in batches */
    int total_ports = config.port_end - config.port_start + 1;
    result.total_scanned = total_ports;

    int ports[MAX_CONCURRENT];
    int current_port = config.port_start;

    while (current_port <= config.port_end) {
        int batch_count = 0;
        for (int i = 0; i < config.batch_size && current_port <= config.port_end; i++, current_port++) {
            ports[batch_count++] = current_port;
        }
        probe_batch(config.ip, ports, batch_count, config.timeout_ms, config.banner_grab, &result);
    }

    gettimeofday(&end, NULL);
    result.scan_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;

    /* Sort open ports */
    for (int i = 0; i < result.count - 1; i++) {
        for (int j = i + 1; j < result.count; j++) {
            if (result.ports[i].port > result.ports[j].port) {
                OpenPort tmp = result.ports[i];
                result.ports[i] = result.ports[j];
                result.ports[j] = tmp;
            }
        }
    }

    /* Output */
    if (config.json_output) {
        output_json(&config, &result);
    } else {
        output_text(&config, &result);
    }

    return 0;
}
