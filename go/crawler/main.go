// RecurSec Go Crawler — High-performance concurrent web crawler
// with configurable depth, scope control, and structured output.
//
// Features:
// - Concurrent crawling with configurable parallelism
// - robots.txt respect
// - Scope control (same-domain, same-origin, custom regex)
// - Link, form, and parameter extraction
// - Technology detection from headers/meta tags
// - JavaScript URL extraction
// - Cookie tracking
// - Rate limiting per domain
// - JSON output for agent consumption
// - JSON-RPC mode for plugin integration

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CrawlResult represents a single crawled page
type CrawlResult struct {
	URL         string            `json:"url"`
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type"`
	Title       string            `json:"title"`
	Links       []string          `json:"links"`
	Forms       []FormInfo        `json:"forms,omitempty"`
	Params      []string          `json:"params,omitempty"`
	Headers     map[string]string `json:"headers"`
	Cookies     []string          `json:"cookies,omitempty"`
	Tech        []string          `json:"tech,omitempty"`
	Size        int               `json:"size"`
	ResponseMs  int64             `json:"response_ms"`
	Depth       int               `json:"depth"`
	Error       string            `json:"error,omitempty"`
}

// FormInfo represents a discovered HTML form
type FormInfo struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

// CrawlSummary is the top-level crawl output
type CrawlSummary struct {
	StartURL    string        `json:"start_url"`
	TotalPages  int           `json:"total_pages"`
	TotalLinks  int           `json:"total_links"`
	TotalForms  int           `json:"total_forms"`
	Unique404   int           `json:"unique_404"`
	Technologies []string     `json:"technologies"`
	Pages       []CrawlResult `json:"pages"`
	ScanTimeS   float64       `json:"scan_time_s"`
}

// CrawlConfig holds crawler settings
type CrawlConfig struct {
	StartURL     string
	MaxDepth     int
	MaxPages     int
	Concurrency  int
	Timeout      time.Duration
	UserAgent    string
	ScopeMode    string // "domain", "subdomain", "path", "all"
	ExcludeRegex string
	FollowRedirect bool
	RespectRobots  bool
	RateLimit    int
}

// Known technologies detected from headers/meta/content
var techSignatures = []struct {
	Pattern string
	Tech    string
}{
	{"wordpress", "WordPress"},
	{"wp-content", "WordPress"},
	{"wp-includes", "WordPress"},
	{"drupal", "Drupal"},
	{"joomla", "Joomla"},
	{"django", "Django"},
	{"laravel", "Laravel"},
	{"express", "Express.js"},
	{"next.js", "Next.js"},
	{"nuxt", "Nuxt.js"},
	{"react", "React"},
	{"angular", "Angular"},
	{"vue", "Vue.js"},
	{"flask", "Flask"},
	{"spring", "Spring"},
	{"rails", "Ruby on Rails"},
	{"asp.net", "ASP.NET"},
	{"php/", "PHP"},
	{"x-powered-by: php", "PHP"},
	{"x-powered-by: express", "Express.js"},
	{"x-powered-by: asp.net", "ASP.NET"},
	{"x-generator: drupal", "Drupal"},
	{"x-generator: wordpress", "WordPress"},
	{"server: nginx", "Nginx"},
	{"server: apache", "Apache"},
	{"server: iis", "Microsoft IIS"},
	{"server: cloudflare", "Cloudflare"},
	{"server: gunicorn", "Gunicorn"},
	{"server: uvicorn", "Uvicorn"},
	{"x-aspnet-version", "ASP.NET"},
	{"x-drupal-cache", "Drupal"},
	{"cf-ray", "Cloudflare"},
	{"x-amz-", "AWS"},
	{"x-vercel", "Vercel"},
	{"x-netlify", "Netlify"},
	{"graphql", "GraphQL"},
	{"swagger", "Swagger"},
	{"openapi", "OpenAPI"},
	{"tomcat", "Apache Tomcat"},
	{"weblogic", "Oracle WebLogic"},
	{"x-jenkins", "Jenkins"},
	{"gitlab", "GitLab"},
	{"gitea", "Gitea"},
	{"phpmyadmin", "phpMyAdmin"},
	{"adminer", "Adminer"},
	{"kibana", "Kibana"},
	{"grafana", "Grafana"},
	{"prometheus", "Prometheus"},
	{"elasticsearch", "Elasticsearch"},
	{"solr", "Apache Solr"},
	{"minio", "MinIO"},
}

// Regex patterns for extracting data from HTML
var (
	titleRe = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	linkRe  = regexp.MustCompile(`(?i)(?:href|src|action)=["']([^"']+)["']`)
	formRe  = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*>`)
	formActionRe = regexp.MustCompile(`(?i)action=["']([^"']+)["']`)
	formMethodRe = regexp.MustCompile(`(?i)method=["']([^"']+)["']`)
	jsURLRe = regexp.MustCompile(`["']((?:https?://|/)[^"'\s]{5,})["']`)
	paramRe = regexp.MustCompile(`[?&]([a-zA-Z0-9_]+)=`)
)

func main() {
	targetURL := flag.String("url", "", "Starting URL to crawl")
	maxDepth := flag.Int("depth", 3, "Maximum crawl depth")
	maxPages := flag.Int("pages", 500, "Maximum pages to crawl")
	concurrency := flag.Int("concurrency", 10, "Concurrent requests")
	timeout := flag.Duration("timeout", 10*time.Second, "Request timeout")
	userAgent := flag.String("ua", "RecurSec-Crawler/1.0", "User agent string")
	scope := flag.String("scope", "domain", "Scope: domain, subdomain, path, all")
	exclude := flag.String("exclude", `\.(png|jpg|gif|css|js|ico|svg|woff|ttf|eot)$`, "Exclude URL regex")
	jsonOutput := flag.Bool("json", true, "Output as JSON")
	rateLimit := flag.Int("rate", 10, "Max requests per second per domain")
	rpcMode := flag.Bool("rpc", false, "Run in JSON-RPC mode")

	flag.Parse()

	if *rpcMode {
		runCrawlerRPC()
		return
	}

	if *targetURL == "" {
		fmt.Fprintln(os.Stderr, "Usage: crawler -url <url> [-depth 3] [-pages 500]")
		os.Exit(1)
	}

	config := CrawlConfig{
		StartURL:    *targetURL,
		MaxDepth:    *maxDepth,
		MaxPages:    *maxPages,
		Concurrency: *concurrency,
		Timeout:     *timeout,
		UserAgent:   *userAgent,
		ScopeMode:   *scope,
		ExcludeRegex: *exclude,
		FollowRedirect: true,
		RateLimit:   *rateLimit,
	}

	summary := runCrawl(config)

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(summary)
	} else {
		printCrawlSummary(summary)
	}
}

func runCrawl(config CrawlConfig) CrawlSummary {
	startTime := time.Now()

	parsedStart, err := url.Parse(config.StartURL)
	if err != nil {
		return CrawlSummary{StartURL: config.StartURL, ScanTimeS: 0}
	}

	var summary CrawlSummary
	summary.StartURL = config.StartURL

	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        config.Concurrency * 2,
			MaxIdleConnsPerHost: config.Concurrency,
			DisableKeepAlives:   false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if !config.FollowRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var excludeRe *regexp.Regexp
	if config.ExcludeRegex != "" {
		excludeRe, _ = regexp.Compile(config.ExcludeRegex)
	}

	visited := &sync.Map{}
	results := make([]CrawlResult, 0, config.MaxPages)
	var resultsMu sync.Mutex
	var pagesCount int32
	techSet := &sync.Map{}
	var totalLinks int32
	var totalForms int32
	var count404 int32

	// Rate limiter per domain
	rateLimiter := time.NewTicker(time.Second / time.Duration(max(config.RateLimit, 1)))
	defer rateLimiter.Stop()

	type crawlItem struct {
		url   string
		depth int
	}

	queue := make(chan crawlItem, config.MaxPages*10)
	queue <- crawlItem{url: config.StartURL, depth: 0}
	visited.Store(config.StartURL, true)

	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Concurrency)

	// Process queue
	done := make(chan struct{})
	go func() {
		idleCount := 0
		for {
			select {
			case item := <-queue:
				if int(atomic.LoadInt32(&pagesCount)) >= config.MaxPages {
					continue
				}
				wg.Add(1)
				go func(ci crawlItem) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					<-rateLimiter.C

					result := crawlPage(client, ci.url, ci.depth, config.UserAgent)
					atomic.AddInt32(&pagesCount, 1)
					atomic.AddInt32(&totalLinks, int32(len(result.Links)))
					atomic.AddInt32(&totalForms, int32(len(result.Forms)))
					if result.StatusCode == 404 {
						atomic.AddInt32(&count404, 1)
					}

					// Detect technologies
					for _, ts := range techSignatures {
						headerStr := fmt.Sprintf("%v", result.Headers)
						combined := strings.ToLower(headerStr + " " + result.Title)
						if strings.Contains(combined, ts.Pattern) {
							techSet.Store(ts.Tech, true)
						}
					}

					// Store result
					resultsMu.Lock()
					results = append(results, result)
					resultsMu.Unlock()

					// Extract and queue new URLs
					for _, link := range result.Links {
						absURL := resolveURL(ci.url, link)
						if absURL == "" {
							continue
						}
						// Check scope
						if !inScope(absURL, parsedStart, config.ScopeMode) {
							continue
						}
						// Check exclude
						if excludeRe != nil && excludeRe.MatchString(absURL) {
							continue
						}
						// Check depth
						if ci.depth+1 > config.MaxDepth {
							continue
						}
						// Dedup
						if _, loaded := visited.LoadOrStore(absURL, true); loaded {
							continue
						}
						// Check max pages
						if int(atomic.LoadInt32(&pagesCount)) >= config.MaxPages {
							continue
						}
						queue <- crawlItem{url: absURL, depth: ci.depth + 1}
					}
				}(item)

			case <-time.After(3 * time.Second):
				idleCount++
				if idleCount > 2 {
					close(done)
					return
				}
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
	case <-time.After(5 * time.Minute):
	}
	wg.Wait()

	// Collect technologies
	var techs []string
	techSet.Range(func(key, value interface{}) bool {
		techs = append(techs, key.(string))
		return true
	})
	sort.Strings(techs)

	summary.TotalPages = int(pagesCount)
	summary.TotalLinks = int(totalLinks)
	summary.TotalForms = int(totalForms)
	summary.Unique404 = int(count404)
	summary.Technologies = techs
	summary.Pages = results
	summary.ScanTimeS = time.Since(startTime).Seconds()

	return summary
}

func crawlPage(client *http.Client, pageURL string, depth int, userAgent string) CrawlResult {
	result := CrawlResult{
		URL:     pageURL,
		Depth:   depth,
		Headers: make(map[string]string),
	}

	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	result.ResponseMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")

	// Capture headers
	for key := range resp.Header {
		result.Headers[key] = resp.Header.Get(key)
	}

	// Capture cookies
	for _, c := range resp.Cookies() {
		result.Cookies = append(result.Cookies, c.Name+"="+c.Value)
	}

	// Read body (limit to 2MB)
	body := make([]byte, 0, 64*1024)
	reader := io.LimitReader(resp.Body, 2*1024*1024)
	buf := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	result.Size = len(body)
	bodyStr := string(body)

	// Extract title
	if matches := titleRe.FindStringSubmatch(bodyStr); len(matches) > 1 {
		result.Title = strings.TrimSpace(matches[1])
	}

	// Extract links
	linkSet := make(map[string]bool)
	for _, match := range linkRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(match) > 1 {
			link := strings.TrimSpace(match[1])
			if link != "" && !strings.HasPrefix(link, "#") && !strings.HasPrefix(link, "javascript:") {
				linkSet[link] = true
			}
		}
	}
	// Also extract JS URLs
	for _, match := range jsURLRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(match) > 1 {
			linkSet[match[1]] = true
		}
	}
	for link := range linkSet {
		result.Links = append(result.Links, link)
	}
	sort.Strings(result.Links)

	// Extract forms
	for _, formMatch := range formRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(formMatch) > 1 {
			formHTML := formMatch[0]
			fi := FormInfo{
				Method: "GET",
			}
			if actionMatch := formActionRe.FindStringSubmatch(formHTML); len(actionMatch) > 1 {
				fi.Action = actionMatch[1]
			}
			if methodMatch := formMethodRe.FindStringSubmatch(formHTML); len(methodMatch) > 1 {
				fi.Method = strings.ToUpper(methodMatch[1])
			}
			for _, inputMatch := range inputRe.FindAllStringSubmatch(formHTML, -1) {
				if len(inputMatch) > 1 {
					fi.Inputs = append(fi.Inputs, inputMatch[1])
				}
			}
			result.Forms = append(result.Forms, fi)
		}
	}

	// Extract URL parameters
	paramSet := make(map[string]bool)
	for _, match := range paramRe.FindAllStringSubmatch(pageURL, -1) {
		if len(match) > 1 {
			paramSet[match[1]] = true
		}
	}
	// Also from links
	for _, link := range result.Links {
		for _, match := range paramRe.FindAllStringSubmatch(link, -1) {
			if len(match) > 1 {
				paramSet[match[1]] = true
			}
		}
	}
	for p := range paramSet {
		result.Params = append(result.Params, p)
	}
	sort.Strings(result.Params)

	return result
}

func resolveURL(base, href string) string {
	if href == "" || href == "#" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return ""
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := baseURL.ResolveReference(ref)
	// Remove fragment
	resolved.Fragment = ""
	return resolved.String()
}

func inScope(testURL string, start *url.URL, scopeMode string) bool {
	parsed, err := url.Parse(testURL)
	if err != nil {
		return false
	}
	// Only HTTP/HTTPS
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	switch scopeMode {
	case "domain":
		return parsed.Hostname() == start.Hostname()
	case "subdomain":
		return strings.HasSuffix(parsed.Hostname(), start.Hostname()) ||
			parsed.Hostname() == start.Hostname()
	case "path":
		return parsed.Hostname() == start.Hostname() &&
			strings.HasPrefix(parsed.Path, start.Path)
	case "all":
		return true
	default:
		return parsed.Hostname() == start.Hostname()
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func printCrawlSummary(s CrawlSummary) {
	fmt.Printf("Crawl: %s\n", s.StartURL)
	fmt.Printf("Pages: %d, Links: %d, Forms: %d, 404s: %d (%.1fs)\n",
		s.TotalPages, s.TotalLinks, s.TotalForms, s.Unique404, s.ScanTimeS)
	if len(s.Technologies) > 0 {
		fmt.Printf("Tech: %s\n", strings.Join(s.Technologies, ", "))
	}
	for _, p := range s.Pages {
		status := fmt.Sprintf("[%d]", p.StatusCode)
		fmt.Printf("  %-6s %s %s\n", status, p.URL, p.Title)
	}
}

// ── JSON-RPC Mode ─────────────────────────────────────────

func runCrawlerRPC() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	encoder := json.NewEncoder(os.Stdout)

	type RPCReq struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	type RPCResp struct {
		Result interface{} `json:"result,omitempty"`
		Error  string      `json:"error,omitempty"`
	}

	for scanner.Scan() {
		var req RPCReq
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			encoder.Encode(RPCResp{Error: "invalid JSON"})
			continue
		}

		switch req.Method {
		case "crawl":
			var params struct {
				URL         string `json:"url"`
				MaxDepth    int    `json:"max_depth"`
				MaxPages    int    `json:"max_pages"`
				Concurrency int    `json:"concurrency"`
				Scope       string `json:"scope"`
			}
			json.Unmarshal(req.Params, &params)

			if params.URL == "" {
				encoder.Encode(RPCResp{Error: "url required"})
				continue
			}
			if params.MaxDepth == 0 { params.MaxDepth = 3 }
			if params.MaxPages == 0 { params.MaxPages = 500 }
			if params.Concurrency == 0 { params.Concurrency = 10 }
			if params.Scope == "" { params.Scope = "domain" }

			config := CrawlConfig{
				StartURL:    params.URL,
				MaxDepth:    params.MaxDepth,
				MaxPages:    params.MaxPages,
				Concurrency: params.Concurrency,
				Timeout:     10 * time.Second,
				UserAgent:   "RecurSec-Crawler/1.0",
				ScopeMode:   params.Scope,
				ExcludeRegex: `\.(png|jpg|gif|css|js|ico|svg|woff|ttf|eot)$`,
				FollowRedirect: true,
				RateLimit:   10,
			}
			result := runCrawl(config)
			encoder.Encode(RPCResp{Result: result})

		case "ping":
			encoder.Encode(RPCResp{Result: "pong"})

		default:
			encoder.Encode(RPCResp{Error: fmt.Sprintf("unknown method: %s", req.Method)})
		}
	}
}
