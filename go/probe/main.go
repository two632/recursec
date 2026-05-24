// Package main — High-performance HTTP probe engine for RecurSec.
//
// Probes thousands of URLs concurrently to:
// 1. Detect live hosts and web servers
// 2. Fingerprint technology stack (server headers, response patterns)
// 3. Capture response metadata (status, headers, title, redirects)
// 4. Detect interesting patterns (login pages, admin panels, APIs)
// 5. Screenshot capabilities via headless Chrome
// 6. Follow redirect chains
// 7. Detect WAFs

package main

import (
	"bufio"
	"context"
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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProbeResult struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	ContentLength  int64             `json:"content_length"`
	ContentType    string            `json:"content_type"`
	Title          string            `json:"title,omitempty"`
	Server         string            `json:"server,omitempty"`
	Technologies   []string          `json:"technologies,omitempty"`
	RedirectChain  []string          `json:"redirect_chain,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	WAF            string            `json:"waf,omitempty"`
	TLSVersion     string            `json:"tls_version,omitempty"`
	TLSCipher      string            `json:"tls_cipher,omitempty"`
	CertIssuer     string            `json:"cert_issuer,omitempty"`
	CertExpiry     string            `json:"cert_expiry,omitempty"`
	Interesting    []string          `json:"interesting,omitempty"`
	Latency        int64             `json:"latency_ms"`
	Error          string            `json:"error,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

// Technology fingerprints from response headers/body
var techFingerprints = []struct {
	Name    string
	Header  string
	Pattern string
}{
	{"Apache", "Server", "(?i)apache"},
	{"Nginx", "Server", "(?i)nginx"},
	{"IIS", "Server", "(?i)microsoft-iis"},
	{"Cloudflare", "Server", "(?i)cloudflare"},
	{"LiteSpeed", "Server", "(?i)litespeed"},
	{"Express", "X-Powered-By", "(?i)express"},
	{"PHP", "X-Powered-By", "(?i)php"},
	{"ASP.NET", "X-Powered-By", "(?i)asp\\.net"},
	{"Django", "X-Framework", "(?i)django"},
	{"Rails", "X-Powered-By", "(?i)phusion passenger"},
	{"WordPress", "", "(?i)wp-content|wp-includes"},
	{"Drupal", "", "(?i)drupal|sites/default"},
	{"Joomla", "", "(?i)/administrator/|joomla"},
	{"React", "", "(?i)react-root|__next|_next/static"},
	{"Angular", "", "(?i)ng-version|ng-app"},
	{"Vue", "", "(?i)vue-app|__vue__"},
}

// WAF detection patterns
var wafPatterns = []struct {
	Name   string
	Header string
	Value  string
}{
	{"Cloudflare", "cf-ray", ""},
	{"Akamai", "x-akamai-transformed", ""},
	{"AWS WAF", "x-amzn-waf-action", ""},
	{"Incapsula", "x-iinfo", ""},
	{"Sucuri", "x-sucuri-id", ""},
	{"ModSecurity", "server", "(?i)mod_security"},
	{"F5 BIG-IP", "server", "(?i)big-ip"},
	{"Barracuda", "server", "(?i)barracuda"},
}

// Interesting patterns in responses
var interestingPatterns = []struct {
	Name    string
	Pattern string
}{
	{"Login Page", "(?i)(login|signin|sign-in|log-in)\\s*(form|page|button)"},
	{"Admin Panel", "(?i)(admin|administrator|dashboard|control.?panel)"},
	{"API Docs", "(?i)(swagger|openapi|api.?doc|graphiql|graphql.?playground)"},
	{"File Upload", "(?i)(upload|file.?input|multipart|dropzone)"},
	{"Debug Mode", "(?i)(debug|stack.?trace|traceback|error.?detail)"},
	{"Version Info", "(?i)(version|v\\d+\\.\\d+|build.?number)"},
	{"Database Error", "(?i)(sql|mysql|postgres|oracle|sqlite|mongodb).*(error|exception|syntax)"},
	{"Backup File", "(?i)\\.(bak|backup|old|orig|copy|swp|tmp)"},
	{"Config File", `(?i)(config|settings|env|properties|\.ini|\.yml|\.yaml)`},
	{"Git Exposed", "(?i)(\\.git/|gitignore|git.?config)"},
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

type Prober struct {
	client     *http.Client
	workers    int
	probed     int64
	errors     int64
	live       int64
	mu         sync.Mutex
}

func NewProber(workers int, timeout time.Duration, followRedirects bool) *Prober {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        workers * 2,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	if !followRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Prober{
		client:  client,
		workers: workers,
	}
}

func (p *Prober) Probe(ctx context.Context, targetURL string) ProbeResult {
	result := ProbeResult{
		URL:       targetURL,
		Timestamp: time.Now(),
		Headers:   make(map[string]string),
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := p.client.Do(req)
	result.Latency = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		atomic.AddInt64(&p.errors, 1)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength
	result.ContentType = resp.Header.Get("Content-Type")
	result.Server = resp.Header.Get("Server")

	// Capture headers
	for key, vals := range resp.Header {
		if len(vals) > 0 {
			result.Headers[key] = vals[0]
		}
	}

	// TLS info
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS10:
			result.TLSVersion = "TLS 1.0"
		case tls.VersionTLS11:
			result.TLSVersion = "TLS 1.1"
		case tls.VersionTLS12:
			result.TLSVersion = "TLS 1.2"
		case tls.VersionTLS13:
			result.TLSVersion = "TLS 1.3"
		}
		result.TLSCipher = tls.CipherSuiteName(resp.TLS.CipherSuite)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			result.CertIssuer = cert.Issuer.CommonName
			result.CertExpiry = cert.NotAfter.Format(time.RFC3339)
		}
	}

	// Read body (limited)
	bodyBytes := make([]byte, 64*1024) // 64KB max
	n, _ := io.ReadFull(resp.Body, bodyBytes)
	body := string(bodyBytes[:n])

	// Extract title
	if matches := titleRegex.FindStringSubmatch(body); len(matches) > 1 {
		result.Title = strings.TrimSpace(matches[1])
		if len(result.Title) > 200 {
			result.Title = result.Title[:200]
		}
	}

	// Technology fingerprinting
	for _, fp := range techFingerprints {
		re := regexp.MustCompile(fp.Pattern)
		if fp.Header != "" {
			headerVal := resp.Header.Get(fp.Header)
			if re.MatchString(headerVal) {
				result.Technologies = append(result.Technologies, fp.Name)
			}
		} else {
			if re.MatchString(body) {
				result.Technologies = append(result.Technologies, fp.Name)
			}
		}
	}

	// WAF detection
	for _, waf := range wafPatterns {
		val := resp.Header.Get(waf.Header)
		if val != "" {
			if waf.Value == "" {
				result.WAF = waf.Name
				break
			}
			if regexp.MustCompile(waf.Value).MatchString(val) {
				result.WAF = waf.Name
				break
			}
		}
	}

	// Interesting pattern detection
	for _, pat := range interestingPatterns {
		re := regexp.MustCompile(pat.Pattern)
		if re.MatchString(body) {
			result.Interesting = append(result.Interesting, pat.Name)
		}
	}

	// Redirect chain
	if resp.Request != nil && resp.Request.URL.String() != targetURL {
		result.RedirectChain = append(result.RedirectChain, resp.Request.URL.String())
	}

	atomic.AddInt64(&p.live, 1)
	return result
}

func (p *Prober) ProbeMany(ctx context.Context, urls []string, output chan<- ProbeResult) {
	jobs := make(chan string, p.workers*2)
	var wg sync.WaitGroup

	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				atomic.AddInt64(&p.probed, 1)
				result := p.Probe(ctx, u)
				if result.Error == "" {
					output <- result
				}
			}
		}()
	}

	for _, u := range urls {
		select {
		case jobs <- u:
		case <-ctx.Done():
			break
		}
	}
	close(jobs)
	wg.Wait()
}

func (p *Prober) Stats() map[string]int64 {
	return map[string]int64{
		"probed": atomic.LoadInt64(&p.probed),
		"live":   atomic.LoadInt64(&p.live),
		"errors": atomic.LoadInt64(&p.errors),
	}
}

func generateURLs(hosts []string, ports []int, https bool) []string {
	var urls []string
	for _, host := range hosts {
		for _, port := range ports {
			scheme := "http"
			if https || port == 443 || port == 8443 {
				scheme = "https"
			}
			if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
				urls = append(urls, fmt.Sprintf("%s://%s", scheme, host))
			} else {
				urls = append(urls, fmt.Sprintf("%s://%s:%d", scheme, host, port))
			}
		}
	}
	return urls
}

func main() {
	inputFile := flag.String("input", "", "File with URLs (one per line)")
	domain := flag.String("domain", "", "Single domain to probe")
	workers := flag.Int("workers", 50, "Concurrent workers")
	timeout := flag.Duration("timeout", 10*time.Second, "Per-request timeout")
	followRedirects := flag.Bool("follow", true, "Follow redirects")
	outputJSON := flag.Bool("json", false, "JSON output")
	ports := flag.String("ports", "80,443,8080,8443", "Ports to probe (comma-separated)")
	flag.Parse()

	var urls []string

	if *inputFile != "" {
		f, err := os.Open(*inputFile)
		if err != nil {
			log.Fatalf("Failed to open input: %v", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				if strings.HasPrefix(line, "http") {
					urls = append(urls, line)
				} else {
					// Treat as host, generate URLs
					var portList []int
					for _, p := range strings.Split(*ports, ",") {
						var port int
						fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
						if port > 0 {
							portList = append(portList, port)
						}
					}
					urls = append(urls, generateURLs([]string{line}, portList, false)...)
				}
			}
		}
	} else if *domain != "" {
		var portList []int
		for _, p := range strings.Split(*ports, ",") {
			var port int
			fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
			if port > 0 {
				portList = append(portList, port)
			}
		}
		urls = generateURLs([]string{*domain}, portList, false)
	} else {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				if strings.HasPrefix(line, "http") {
					urls = append(urls, line)
				} else {
					urls = append(urls, fmt.Sprintf("http://%s", line))
					urls = append(urls, fmt.Sprintf("https://%s", line))
				}
			}
		}
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "No URLs to probe. Use -input, -domain, or pipe URLs via stdin.")
		os.Exit(1)
	}

	parsed := make([]string, 0, len(urls))
	for _, u := range urls {
		if _, err := url.Parse(u); err == nil {
			parsed = append(parsed, u)
		}
	}
	urls = parsed

	log.Printf("Probing %d URLs with %d workers...", len(urls), *workers)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	prober := NewProber(*workers, *timeout, *followRedirects)
	output := make(chan ProbeResult, 1000)

	go func() {
		prober.ProbeMany(ctx, urls, output)
		close(output)
	}()

	found := 0
	for result := range output {
		found++
		if *outputJSON {
			data, _ := json.Marshal(result)
			fmt.Println(string(data))
		} else {
			techs := ""
			if len(result.Technologies) > 0 {
				techs = " [" + strings.Join(result.Technologies, ",") + "]"
			}
			waf := ""
			if result.WAF != "" {
				waf = " WAF:" + result.WAF
			}
			interest := ""
			if len(result.Interesting) > 0 {
				interest = " !" + strings.Join(result.Interesting, ",")
			}
			fmt.Printf("[%d] %s %dms%s%s%s %s\n",
				result.StatusCode, result.URL, result.Latency,
				techs, waf, interest, result.Title)
		}
	}

	stats := prober.Stats()
	log.Printf("Done. Probed: %d, Live: %d, Errors: %d",
		stats["probed"], stats["live"], stats["errors"])
}
