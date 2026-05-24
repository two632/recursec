// RecurSec Web Spider
//
// Concurrent web spider for discovering URLs, forms, parameters:
// - Breadth-first crawling with configurable depth
// - Concurrent workers with rate limiting
// - Form detection and parameter extraction
// - JavaScript endpoint extraction
// - Scope enforcement (same domain only)
// - JSON output for agent consumption
//
// Usage: ./spider --url https://example.com --depth 3 --workers 10 --json

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PageResult struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Title       string   `json:"title,omitempty"`
	Forms       []Form   `json:"forms,omitempty"`
	Links       []string `json:"links,omitempty"`
	Params      []string `json:"params,omitempty"`
	JSEndpoints []string `json:"js_endpoints,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Size        int      `json:"size"`
	Depth       int      `json:"depth"`
}

type Form struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

type SpiderConfig struct {
	BaseURL   string
	MaxDepth  int
	Workers   int
	RateLimit time.Duration
	Timeout   time.Duration
	UserAgent string
	JSON      bool
	MaxPages  int
}

type Spider struct {
	config   SpiderConfig
	client   *http.Client
	visited  map[string]bool
	results  []PageResult
	queue    chan crawlTask
	mu       sync.Mutex
	wg       sync.WaitGroup
	baseHost string
}

type crawlTask struct {
	URL   string
	Depth int
}

var (
	linkRe       = regexp.MustCompile(`href=["']([^"'#]+)["']`)
	titleRe      = regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
	formRe       = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	formActionRe = regexp.MustCompile(`action=["']([^"']+)["']`)
	formMethodRe = regexp.MustCompile(`method=["']([^"']+)["']`)
	inputRe      = regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*>`)
	jsEndpointRe = regexp.MustCompile(`["'](/api/[^"']+|/v[0-9]+/[^"']+)["']`)
	paramRe      = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)=`)
)

func NewSpider(config SpiderConfig) *Spider {
	parsedURL, _ := url.Parse(config.BaseURL)
	host := ""
	if parsedURL != nil {
		host = parsedURL.Host
	}
	return &Spider{
		config:   config,
		client:   &http.Client{Timeout: config.Timeout},
		visited:  make(map[string]bool),
		queue:    make(chan crawlTask, config.MaxPages*2),
		baseHost: host,
	}
}

func (s *Spider) Run(ctx context.Context) []PageResult {
	for i := 0; i < s.config.Workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.queue <- crawlTask{URL: s.config.BaseURL, Depth: 0}

	baseURL, _ := url.Parse(s.config.BaseURL)
	if baseURL != nil {
		robotsURL := fmt.Sprintf("%s://%s/robots.txt", baseURL.Scheme, baseURL.Host)
		sitemapURL := fmt.Sprintf("%s://%s/sitemap.xml", baseURL.Scheme, baseURL.Host)
		s.queue <- crawlTask{URL: robotsURL, Depth: 1}
		s.queue <- crawlTask{URL: sitemapURL, Depth: 1}
	}

	go func() {
		lastSize := 0
		staleCount := 0
		for {
			time.Sleep(2 * time.Second)
			s.mu.Lock()
			currentSize := len(s.results)
			s.mu.Unlock()
			if currentSize == lastSize {
				staleCount++
				if staleCount >= 3 {
					close(s.queue)
					return
				}
			} else {
				staleCount = 0
			}
			lastSize = currentSize
		}
	}()

	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.results
}

func (s *Spider) worker(ctx context.Context) {
	defer s.wg.Done()
	for task := range s.queue {
		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(s.config.RateLimit)

		s.mu.Lock()
		if s.visited[task.URL] || len(s.results) >= s.config.MaxPages {
			s.mu.Unlock()
			continue
		}
		s.visited[task.URL] = true
		s.mu.Unlock()

		result := s.crawlPage(task.URL, task.Depth)
		if result != nil {
			s.mu.Lock()
			s.results = append(s.results, *result)
			s.mu.Unlock()

			if task.Depth < s.config.MaxDepth {
				for _, link := range result.Links {
					s.mu.Lock()
					skip := s.visited[link]
					s.mu.Unlock()
					if !skip && s.inScope(link) {
						select {
						case s.queue <- crawlTask{URL: link, Depth: task.Depth + 1}:
						default:
						}
					}
				}
			}
		}
	}
}

func (s *Spider) crawlPage(pageURL string, depth int) *PageResult {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", s.config.UserAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	result := &PageResult{
		URL:         pageURL,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Size:        len(body),
		Depth:       depth,
	}

	if m := titleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		result.Title = strings.TrimSpace(m[1])
	}

	seen := make(map[string]bool)
	for _, m := range linkRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) > 1 {
			resolved := s.resolveURL(pageURL, m[1])
			if resolved != "" && !seen[resolved] {
				result.Links = append(result.Links, resolved)
				seen[resolved] = true
			}
		}
	}

	for _, fm := range formRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(fm) > 1 {
			form := Form{Method: "GET"}
			if am := formActionRe.FindStringSubmatch(fm[0]); len(am) > 1 {
				form.Action = s.resolveURL(pageURL, am[1])
			}
			if mm := formMethodRe.FindStringSubmatch(fm[0]); len(mm) > 1 {
				form.Method = strings.ToUpper(mm[1])
			}
			for _, im := range inputRe.FindAllStringSubmatch(fm[1], -1) {
				if len(im) > 1 {
					form.Inputs = append(form.Inputs, im[1])
				}
			}
			result.Forms = append(result.Forms, form)
		}
	}

	for _, pm := range paramRe.FindAllStringSubmatch(pageURL, -1) {
		if len(pm) > 1 {
			result.Params = append(result.Params, pm[1])
		}
	}

	for _, jm := range jsEndpointRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(jm) > 1 {
			result.JSEndpoints = append(result.JSEndpoints, jm[1])
		}
	}

	return result
}

func (s *Spider) resolveURL(base, href string) string {
	if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
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
	resolved.Fragment = ""
	return resolved.String()
}

func (s *Spider) inScope(targetURL string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return parsed.Host == s.baseHost
}

func main() {
	config := SpiderConfig{
		MaxDepth:  3,
		Workers:   10,
		RateLimit: 200 * time.Millisecond,
		Timeout:   10 * time.Second,
		UserAgent: "RecurSec-Spider/1.0",
		MaxPages:  500,
	}

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--url":
			if i+1 < len(args) {
				config.BaseURL = args[i+1]
				i++
			}
		case "--depth":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					config.MaxDepth = n
				}
				i++
			}
		case "--workers":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					config.Workers = n
				}
				i++
			}
		case "--max-pages":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					config.MaxPages = n
				}
				i++
			}
		case "--json":
			config.JSON = true
		case "--rate":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					config.RateLimit = d
				}
				i++
			}
		}
	}

	if config.BaseURL == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --url <target> [--depth 3] [--workers 10] [--max-pages 500] [--json]\n", os.Args[0])
		os.Exit(1)
	}

	spider := NewSpider(config)
	ctx := context.Background()

	if !config.JSON {
		log.Printf("Starting spider: %s (depth=%d, workers=%d)", config.BaseURL, config.MaxDepth, config.Workers)
	}

	results := spider.Run(ctx)

	if config.JSON {
		output := map[string]interface{}{
			"base_url":    config.BaseURL,
			"pages_found": len(results),
			"results":     results,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(output)
	} else {
		fmt.Printf("\nSpider Results for %s:\n", config.BaseURL)
		fmt.Printf("Pages crawled: %d\n\n", len(results))
		totalForms := 0
		for _, r := range results {
			fmt.Printf("  [%d] %s (%d bytes)\n", r.StatusCode, r.URL, r.Size)
			totalForms += len(r.Forms)
			for _, f := range r.Forms {
				fmt.Printf("       Form: %s %s → %s\n", f.Method, f.Action, strings.Join(f.Inputs, ", "))
			}
		}
		fmt.Printf("\nSummary: %d pages, %d forms\n", len(results), totalForms)
	}
}
