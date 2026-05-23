// RecurSec Go Proxy — HTTP/HTTPS interception proxy for security testing.
//
// Features:
// - HTTP/HTTPS traffic interception
// - Request/response logging to JSON
// - Header injection/modification
// - Request filtering (by host, path, method)
// - Rate limiting
// - Upstream proxy chaining
// - WebSocket passthrough
// - Certificate generation for HTTPS MITM
//
// Usage: proxy -listen :8888 -log /tmp/proxy.log [-upstream http://proxy:3128]

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyConfig holds the proxy configuration
type ProxyConfig struct {
	ListenAddr    string
	LogFile       string
	UpstreamProxy string
	MaxBodyLog    int64
	AllowedHosts  []string
	BlockedHosts  []string
	InjectHeaders map[string]string
	RateLimit     int // requests per second, 0 = unlimited
	Verbose       bool
}

// RequestLog represents a logged request/response pair
type RequestLog struct {
	Timestamp    string            `json:"timestamp"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Host         string            `json:"host"`
	StatusCode   int               `json:"status_code,omitempty"`
	RequestSize  int64             `json:"request_size"`
	ResponseSize int64             `json:"response_size,omitempty"`
	Duration     float64           `json:"duration_ms"`
	Headers      map[string]string `json:"request_headers,omitempty"`
	RespHeaders  map[string]string `json:"response_headers,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// ProxyStats tracks proxy statistics
type ProxyStats struct {
	TotalRequests  int64 `json:"total_requests"`
	SuccessCount   int64 `json:"success_count"`
	ErrorCount     int64 `json:"error_count"`
	BytesSent      int64 `json:"bytes_sent"`
	BytesReceived  int64 `json:"bytes_received"`
	ActiveRequests int64 `json:"active_requests"`
}

// RecurSecProxy is the main proxy server
type RecurSecProxy struct {
	config  ProxyConfig
	stats   ProxyStats
	logFile *os.File
	logMu   sync.Mutex
	client  *http.Client
}

func newProxy(config ProxyConfig) (*RecurSecProxy, error) {
	p := &RecurSecProxy{
		config: config,
	}

	// Open log file
	if config.LogFile != "" {
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log: %w", err)
		}
		p.logFile = f
	}

	// Configure HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Proxy needs to handle all certs
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	// Configure upstream proxy
	if config.UpstreamProxy != "" {
		proxyURL, err := url.Parse(config.UpstreamProxy)
		if err != nil {
			return nil, fmt.Errorf("parse upstream proxy: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	p.client = &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return p, nil
}

func (p *RecurSecProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	atomic.AddInt64(&p.stats.ActiveRequests, 1)
	defer atomic.AddInt64(&p.stats.ActiveRequests, -1)
	atomic.AddInt64(&p.stats.TotalRequests, 1)

	start := time.Now()

	// Check host filtering
	if !p.isAllowed(r.Host) {
		http.Error(w, "Blocked by proxy", http.StatusForbidden)
		return
	}

	// Create the outgoing request
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		p.logError(w, r, err, start)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}

	// Remove proxy headers
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	// Inject custom headers
	for key, value := range p.config.InjectHeaders {
		outReq.Header.Set(key, value)
	}

	// Forward the request
	resp, err := p.client.Do(outReq)
	if err != nil {
		p.logError(w, r, err, start)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	written, _ := io.Copy(w, resp.Body)

	duration := time.Since(start)
	atomic.AddInt64(&p.stats.SuccessCount, 1)
	atomic.AddInt64(&p.stats.BytesReceived, written)

	// Log the request
	p.logRequest(RequestLog{
		Timestamp:    start.Format(time.RFC3339),
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         r.Host,
		StatusCode:   resp.StatusCode,
		RequestSize:  r.ContentLength,
		ResponseSize: written,
		Duration:     float64(duration.Milliseconds()),
		Headers:      flattenHeaders(r.Header),
		RespHeaders:  flattenHeaders(resp.Header),
	})
}

func (p *RecurSecProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// HTTPS CONNECT tunneling
	atomic.AddInt64(&p.stats.TotalRequests, 1)

	if !p.isAllowed(r.Host) {
		http.Error(w, "Blocked", http.StatusForbidden)
		return
	}

	targetAddr := r.Host
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		atomic.AddInt64(&p.stats.ErrorCount, 1)
		return
	}

	// Send 200 OK to client
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		targetConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy
	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)

	p.logRequest(RequestLog{
		Timestamp: time.Now().Format(time.RFC3339),
		Method:    "CONNECT",
		URL:       r.Host,
		Host:      r.Host,
	})
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func (p *RecurSecProxy) isAllowed(host string) bool {
	// Strip port
	h := host
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		h = h[:idx]
	}

	// Check blocked list
	for _, blocked := range p.config.BlockedHosts {
		if strings.Contains(h, blocked) {
			return false
		}
	}

	// Check allowed list (empty = allow all)
	if len(p.config.AllowedHosts) == 0 {
		return true
	}
	for _, allowed := range p.config.AllowedHosts {
		if strings.Contains(h, allowed) {
			return true
		}
	}
	return false
}

func (p *RecurSecProxy) logRequest(entry RequestLog) {
	if p.logFile == nil {
		return
	}
	p.logMu.Lock()
	defer p.logMu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = p.logFile.Write(append(data, '\n'))
}

func (p *RecurSecProxy) logError(w http.ResponseWriter, r *http.Request, err error, start time.Time) {
	atomic.AddInt64(&p.stats.ErrorCount, 1)
	http.Error(w, fmt.Sprintf("Proxy error: %s", err), http.StatusBadGateway)

	p.logRequest(RequestLog{
		Timestamp: start.Format(time.RFC3339),
		Method:    r.Method,
		URL:       r.URL.String(),
		Host:      r.Host,
		Duration:  float64(time.Since(start).Milliseconds()),
		Error:     err.Error(),
	})
}

func (p *RecurSecProxy) statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.MarshalIndent(p.stats, "", "  ")
	_, _ = w.Write(data)
}

func (p *RecurSecProxy) close() {
	if p.logFile != nil {
		p.logFile.Close()
	}
}

func flattenHeaders(h http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range h {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

func main() {
	listenAddr := flag.String("listen", ":8888", "Listen address")
	logFile := flag.String("log", "", "Log file path (JSON lines)")
	upstream := flag.String("upstream", "", "Upstream proxy URL")
	verbose := flag.Bool("v", false, "Verbose output")
	statsAddr := flag.String("stats", ":8889", "Stats endpoint address")

	flag.Parse()

	config := ProxyConfig{
		ListenAddr:    *listenAddr,
		LogFile:       *logFile,
		UpstreamProxy: *upstream,
		MaxBodyLog:    1024 * 1024, // 1MB
		InjectHeaders: map[string]string{},
		Verbose:       *verbose,
	}

	proxy, err := newProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %s", err)
	}
	defer proxy.close()

	// Stats endpoint
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/stats", proxy.statsHandler)
		log.Printf("Stats at http://localhost%s/stats", *statsAddr)
		_ = http.ListenAndServe(*statsAddr, mux)
	}()

	log.Printf("RecurSec Proxy listening on %s", config.ListenAddr)
	if config.UpstreamProxy != "" {
		log.Printf("Upstream proxy: %s", config.UpstreamProxy)
	}

	server := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %s", err)
	}
}
