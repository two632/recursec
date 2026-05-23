// RecurSec Go Scanner — High-performance concurrent port scanner
// with service fingerprinting and JSON output for agent consumption.
//
// Features:
// - SYN/Connect scanning with configurable concurrency
// - Service banner grabbing and fingerprinting
// - CIDR/range target expansion
// - JSON-RPC interface for plugin integration
// - Rate limiting and timeout control

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanResult represents the result of scanning a single port
type ScanResult struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	State        string `json:"state"`
	Service      string `json:"service"`
	Banner       string `json:"banner"`
	Version      string `json:"version"`
	ResponseMs   int64  `json:"response_ms"`
	Protocol     string `json:"protocol"`
}

// HostResult represents all results for a single host
type HostResult struct {
	IP        string       `json:"ip"`
	Hostname  string       `json:"hostname,omitempty"`
	IsUp      bool         `json:"is_up"`
	OpenPorts []ScanResult `json:"open_ports"`
	ScanTimeS float64      `json:"scan_time_s"`
}

// ScanSummary is the top-level scan output
type ScanSummary struct {
	Targets    []string     `json:"targets"`
	TotalHosts int          `json:"total_hosts"`
	HostsUp    int          `json:"hosts_up"`
	TotalPorts int          `json:"total_ports"`
	OpenPorts  int          `json:"open_ports"`
	Hosts      []HostResult `json:"hosts"`
	ScanTimeS  float64      `json:"scan_time_s"`
}

// Config holds scanner configuration
type Config struct {
	Targets     []string
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	BannerGrab  bool
	RateLimit   int
	OutputJSON  bool
	RPCMode     bool
}

// Well-known port to service mapping
var wellKnownPorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
	119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp",
	389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
	500: "isakmp", 514: "syslog", 515: "printer", 548: "afp",
	554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps",
	873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
	1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
	1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2222: "ssh-alt",
	2375: "docker", 3000: "grafana", 3306: "mysql", 3389: "rdp",
	3690: "svn", 4443: "pharos", 5000: "upnp", 5060: "sip",
	5222: "xmpp", 5432: "postgresql", 5672: "amqp", 5900: "vnc",
	5984: "couchdb", 6000: "x11", 6379: "redis", 6443: "k8s-api",
	6667: "irc", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
	8009: "ajp13", 8080: "http-proxy", 8443: "https-alt",
	8888: "http-alt", 9000: "cslistener", 9042: "cassandra",
	9090: "prometheus", 9200: "elasticsearch", 9418: "git",
	10000: "webmin", 10250: "kubelet", 11211: "memcached",
	15672: "rabbitmq-mgmt", 27017: "mongodb", 50000: "ibm-db2",
}

// Top 100 ports
var top100Ports = []int{
	7, 20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 119, 123,
	135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 464, 465, 500,
	514, 515, 520, 543, 544, 548, 554, 587, 631, 636, 873, 990, 993, 995,
	1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2181, 2222, 2375, 3000,
	3306, 3389, 3690, 4443, 4444, 5000, 5060, 5222, 5432, 5555, 5601, 5672,
	5683, 5900, 5984, 6000, 6379, 6443, 6667, 6697, 7000, 7001, 7443, 8000,
	8008, 8009, 8080, 8081, 8443, 8888, 9000, 9042, 9090, 9100, 9200, 9418,
	9999, 10000, 10250, 11211, 27017,
}

func main() {
	target := flag.String("target", "", "Target to scan (IP, CIDR, hostname)")
	ports := flag.String("ports", "top100", "Ports to scan (e.g., '80,443', '1-1024', 'top100', 'all')")
	concurrency := flag.Int("concurrency", 500, "Maximum concurrent connections")
	timeout := flag.Duration("timeout", 2*time.Second, "Connection timeout")
	banner := flag.Bool("banner", true, "Grab service banners")
	rateLimit := flag.Int("rate", 0, "Max packets per second (0=unlimited)")
	jsonOutput := flag.Bool("json", true, "Output as JSON")
	rpcMode := flag.Bool("rpc", false, "Run in JSON-RPC mode for plugin integration")

	flag.Parse()

	if *rpcMode {
		runRPCMode()
		return
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: scanner -target <ip/cidr> [-ports top100] [-concurrency 500]")
		os.Exit(1)
	}

	config := Config{
		Targets:     expandTarget(*target),
		Ports:       parsePorts(*ports),
		Concurrency: *concurrency,
		Timeout:     *timeout,
		BannerGrab:  *banner,
		RateLimit:   *rateLimit,
		OutputJSON:  *jsonOutput,
	}

	summary := runScan(config)

	if config.OutputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(summary)
	} else {
		printSummary(summary)
	}
}

func runScan(config Config) ScanSummary {
	startTime := time.Now()
	var summary ScanSummary
	summary.Targets = config.Targets
	summary.TotalHosts = len(config.Targets)

	var hostsUp int32
	var totalOpen int32
	totalPorts := len(config.Targets) * len(config.Ports)
	summary.TotalPorts = totalPorts

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Rate limiter
	var rateLimiter <-chan time.Time
	if config.RateLimit > 0 {
		rateLimiter = time.Tick(time.Second / time.Duration(config.RateLimit))
	}

	sem := make(chan struct{}, config.Concurrency)

	for _, host := range config.Targets {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			hostStart := time.Now()
			result := HostResult{IP: h}

			// Resolve hostname
			names, err := net.LookupAddr(h)
			if err == nil && len(names) > 0 {
				result.Hostname = strings.TrimSuffix(names[0], ".")
			}

			var portResults []ScanResult
			var portMu sync.Mutex
			var portWg sync.WaitGroup

			for _, port := range config.Ports {
				portWg.Add(1)
				go func(p int) {
					defer portWg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					if rateLimiter != nil {
						<-rateLimiter
					}

					sr := scanPort(h, p, config.Timeout, config.BannerGrab)
					if sr.State == "open" {
						portMu.Lock()
						portResults = append(portResults, sr)
						portMu.Unlock()
						atomic.AddInt32(&totalOpen, 1)
					}
				}(port)
			}
			portWg.Wait()

			if len(portResults) > 0 {
				result.IsUp = true
				atomic.AddInt32(&hostsUp, 1)
				sort.Slice(portResults, func(i, j int) bool {
					return portResults[i].Port < portResults[j].Port
				})
				result.OpenPorts = portResults
			}
			result.ScanTimeS = time.Since(hostStart).Seconds()

			mu.Lock()
			summary.Hosts = append(summary.Hosts, result)
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	summary.HostsUp = int(hostsUp)
	summary.OpenPorts = int(totalOpen)
	summary.ScanTimeS = time.Since(startTime).Seconds()

	// Sort hosts by IP
	sort.Slice(summary.Hosts, func(i, j int) bool {
		return summary.Hosts[i].IP < summary.Hosts[j].IP
	})

	return summary
}

func scanPort(host string, port int, timeout time.Duration, bannerGrab bool) ScanResult {
	result := ScanResult{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := time.Since(start)
	result.ResponseMs = elapsed.Milliseconds()

	if err != nil {
		if isTimeout(err) {
			result.State = "filtered"
		}
		return result
	}
	defer conn.Close()

	result.State = "open"
	result.Service = wellKnownPorts[port]

	if bannerGrab {
		banner := grabBanner(conn, port, timeout)
		if banner != "" {
			result.Banner = banner
			svc, ver := detectService(banner)
			if svc != "" {
				result.Service = svc
			}
			if ver != "" {
				result.Version = ver
			}
		}
	}

	return result
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Some services send banner immediately
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		return cleanBanner(string(buf[:n]))
	}

	// Try sending a probe
	probes := map[int]string{
		80:   "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
		443:  "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
		8080: "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
		21:   "QUIT\r\n",
		25:   "EHLO scanner\r\n",
		110:  "QUIT\r\n",
		143:  "a001 CAPABILITY\r\n",
	}

	probe, ok := probes[port]
	if !ok {
		probe = "\r\n"
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(probe))

	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err = conn.Read(buf)
	if err == nil && n > 0 {
		return cleanBanner(string(buf[:n]))
	}

	return ""
}

func cleanBanner(banner string) string {
	// Trim and limit length
	banner = strings.TrimSpace(banner)
	if len(banner) > 500 {
		banner = banner[:500]
	}
	// Remove null bytes
	banner = strings.ReplaceAll(banner, "\x00", "")
	return banner
}

func detectService(banner string) (string, string) {
	lower := strings.ToLower(banner)

	signatures := []struct {
		sig     string
		service string
	}{
		{"ssh-2.0-openssh", "ssh"},
		{"ssh-2.0-dropbear", "ssh"},
		{"220 ", "ftp"},
		{"* ok", "imap"},
		{"+ok", "pop3"},
		{"http/1.", "http"},
		{"http/2", "http"},
		{"220 ", "smtp"},
		{"mysql_native_password", "mysql"},
		{"mariadb", "mysql"},
		{"postgresql", "postgresql"},
		{"redis", "redis"},
		{"memcached", "memcached"},
		{"mongodb", "mongodb"},
		{"rfb 00", "vnc"},
	}

	for _, s := range signatures {
		if strings.Contains(lower, s.sig) {
			version := ""
			if strings.Contains(banner, "OpenSSH_") {
				parts := strings.Split(banner, "OpenSSH_")
				if len(parts) > 1 {
					version = "OpenSSH " + strings.Fields(parts[1])[0]
				}
			} else if strings.Contains(banner, "Server:") {
				for _, line := range strings.Split(banner, "\n") {
					if strings.HasPrefix(line, "Server:") {
						version = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
						break
					}
				}
			}
			return s.service, version
		}
	}

	return "", ""
}

func expandTarget(target string) []string {
	// CIDR
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}
	// Range (192.168.1.1-254)
	if strings.Contains(target, "-") {
		return expandRange(target)
	}
	// Single IP or hostname
	ip := net.ParseIP(target)
	if ip == nil {
		// Try resolving hostname
		ips, err := net.LookupHost(target)
		if err == nil && len(ips) > 0 {
			return ips
		}
	}
	return []string{target}
}

func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /24 and smaller
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func expandRange(target string) []string {
	parts := strings.SplitN(target, "-", 2)
	if len(parts) != 2 {
		return []string{target}
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return []string{target}
	}

	endStr := strings.TrimSpace(parts[1])
	var endIP net.IP

	if strings.Contains(endStr, ".") {
		endIP = net.ParseIP(endStr)
	} else {
		// Short form: 192.168.1.1-254
		octets := strings.Split(startIP.String(), ".")
		if len(octets) == 4 {
			octets[3] = endStr
			endIP = net.ParseIP(strings.Join(octets, "."))
		}
	}

	if endIP == nil {
		return []string{target}
	}

	var ips []string
	for ip := dupIP(startIP); !ip.Equal(endIP); incIP(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, endIP.String())
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func parsePorts(spec string) []int {
	switch spec {
	case "top100":
		return top100Ports
	case "all":
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports
	}

	portSet := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, _ := strconv.Atoi(rangeParts[0])
			end, _ := strconv.Atoi(rangeParts[1])
			for p := start; p <= end && p <= 65535; p++ {
				if p >= 1 {
					portSet[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p >= 1 && p <= 65535 {
				portSet[p] = true
			}
		}
	}

	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func printSummary(s ScanSummary) {
	fmt.Printf("Scan complete: %d hosts, %d up, %d open ports (%.1fs)\n",
		s.TotalHosts, s.HostsUp, s.OpenPorts, s.ScanTimeS)
	for _, h := range s.Hosts {
		if !h.IsUp {
			continue
		}
		fmt.Printf("\n%s", h.IP)
		if h.Hostname != "" {
			fmt.Printf(" (%s)", h.Hostname)
		}
		fmt.Println()
		for _, p := range h.OpenPorts {
			svc := p.Service
			if svc == "" {
				svc = "unknown"
			}
			ver := ""
			if p.Version != "" {
				ver = " " + p.Version
			}
			fmt.Printf("  %d/tcp  open  %-16s%s\n", p.Port, svc, ver)
		}
	}
}

// ── JSON-RPC Mode ─────────────────────────────────────────

type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type RPCResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func runRPCMode() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req RPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			encoder.Encode(RPCResponse{Error: "invalid JSON"})
			continue
		}

		switch req.Method {
		case "scan":
			var params struct {
				Target      string `json:"target"`
				Ports       string `json:"ports"`
				Concurrency int    `json:"concurrency"`
				Timeout     int    `json:"timeout_ms"`
				Banner      bool   `json:"banner"`
			}
			json.Unmarshal(req.Params, &params)

			if params.Target == "" {
				encoder.Encode(RPCResponse{Error: "target required"})
				continue
			}
			if params.Concurrency == 0 {
				params.Concurrency = 500
			}
			if params.Timeout == 0 {
				params.Timeout = 2000
			}
			if params.Ports == "" {
				params.Ports = "top100"
			}

			config := Config{
				Targets:     expandTarget(params.Target),
				Ports:       parsePorts(params.Ports),
				Concurrency: params.Concurrency,
				Timeout:     time.Duration(params.Timeout) * time.Millisecond,
				BannerGrab:  params.Banner,
			}

			result := runScan(config)
			encoder.Encode(RPCResponse{Result: result})

		case "ping":
			encoder.Encode(RPCResponse{Result: "pong"})

		default:
			encoder.Encode(RPCResponse{Error: fmt.Sprintf("unknown method: %s", req.Method)})
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "stdin error: %v\n", err)
	}
}
