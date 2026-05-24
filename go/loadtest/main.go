// RecurSec Load Tester
//
// Concurrent HTTP load testing tool for:
// - Stress testing web targets before scanning
// - Measuring response times under load
// - Detecting rate limiting and WAF behavior
// - Finding timing-based vulnerabilities
// - Identifying resource exhaustion issues
//
// Usage: ./loadtest --url https://example.com --rps 50 --duration 30s --json

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	URL      string
	RPS      int
	Duration time.Duration
	Workers  int
	Method   string
	Headers  map[string]string
	Body     string
	JSON     bool
	Verbose  bool
}

type RequestResult struct {
	StatusCode  int           `json:"status_code"`
	Latency     time.Duration `json:"latency_ns"`
	BodySize    int           `json:"body_size"`
	Error       string        `json:"error,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
}

type Summary struct {
	TotalRequests   int64             `json:"total_requests"`
	SuccessCount    int64             `json:"success_count"`
	ErrorCount      int64             `json:"error_count"`
	Duration        float64           `json:"duration_seconds"`
	RPS             float64           `json:"actual_rps"`
	LatencyMin      float64           `json:"latency_min_ms"`
	LatencyMax      float64           `json:"latency_max_ms"`
	LatencyMean     float64           `json:"latency_mean_ms"`
	LatencyMedian   float64           `json:"latency_median_ms"`
	LatencyP95      float64           `json:"latency_p95_ms"`
	LatencyP99      float64           `json:"latency_p99_ms"`
	StatusCodes     map[int]int64     `json:"status_codes"`
	ErrorTypes      map[string]int64  `json:"error_types"`
	RateLimited     bool              `json:"rate_limited"`
	WAFDetected     bool              `json:"waf_detected"`
}

type LoadTester struct {
	config    Config
	client    *http.Client
	results   []RequestResult
	mu        sync.Mutex
	success   int64
	errors    int64
	total     int64
}

func NewLoadTester(config Config) *LoadTester {
	transport := &http.Transport{
		MaxIdleConns:        config.Workers * 2,
		MaxIdleConnsPerHost: config.Workers * 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &LoadTester{
		config: config,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

func (lt *LoadTester) Run(ctx context.Context) Summary {
	ctx, cancel := context.WithTimeout(ctx, lt.config.Duration)
	defer cancel()

	// Calculate interval between requests
	interval := time.Second / time.Duration(lt.config.RPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, lt.config.Workers)

	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			goto done
		case <-ticker.C:
			wg.Add(1)
			semaphore <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-semaphore }()
				lt.sendRequest(ctx)
			}()
		}
	}

done:
	wg.Wait()
	elapsed := time.Since(start)

	return lt.computeSummary(elapsed)
}

func (lt *LoadTester) sendRequest(ctx context.Context) {
	atomic.AddInt64(&lt.total, 1)

	var body io.Reader
	if lt.config.Body != "" {
		body = strings.NewReader(lt.config.Body)
	}

	req, err := http.NewRequestWithContext(ctx, lt.config.Method, lt.config.URL, body)
	if err != nil {
		lt.recordError(err.Error())
		return
	}

	for k, v := range lt.config.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "RecurSec-LoadTest/1.0")

	start := time.Now()
	resp, err := lt.client.Do(req)
	latency := time.Since(start)

	if err != nil {
		lt.recordError(err.Error())
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024))

	result := RequestResult{
		StatusCode: resp.StatusCode,
		Latency:    latency,
		BodySize:   len(bodyBytes),
		Timestamp:  time.Now(),
	}

	lt.mu.Lock()
	lt.results = append(lt.results, result)
	lt.mu.Unlock()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		atomic.AddInt64(&lt.success, 1)
	} else {
		atomic.AddInt64(&lt.errors, 1)
	}
}

func (lt *LoadTester) recordError(errMsg string) {
	atomic.AddInt64(&lt.errors, 1)
	result := RequestResult{
		Error:     errMsg,
		Timestamp: time.Now(),
	}
	lt.mu.Lock()
	lt.results = append(lt.results, result)
	lt.mu.Unlock()
}

func (lt *LoadTester) computeSummary(elapsed time.Duration) Summary {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	summary := Summary{
		TotalRequests: atomic.LoadInt64(&lt.total),
		SuccessCount:  atomic.LoadInt64(&lt.success),
		ErrorCount:    atomic.LoadInt64(&lt.errors),
		Duration:      elapsed.Seconds(),
		StatusCodes:   make(map[int]int64),
		ErrorTypes:    make(map[string]int64),
	}

	if summary.Duration > 0 {
		summary.RPS = float64(summary.TotalRequests) / summary.Duration
	}

	var latencies []float64
	for _, r := range lt.results {
		if r.Error != "" {
			errType := "connection_error"
			if strings.Contains(r.Error, "timeout") {
				errType = "timeout"
			} else if strings.Contains(r.Error, "refused") {
				errType = "connection_refused"
			}
			summary.ErrorTypes[errType]++
			continue
		}
		summary.StatusCodes[r.StatusCode]++
		latencies = append(latencies, float64(r.Latency.Milliseconds()))
	}

	if len(latencies) > 0 {
		sort.Float64s(latencies)
		summary.LatencyMin = latencies[0]
		summary.LatencyMax = latencies[len(latencies)-1]

		sum := 0.0
		for _, l := range latencies {
			sum += l
		}
		summary.LatencyMean = sum / float64(len(latencies))
		summary.LatencyMedian = percentile(latencies, 50)
		summary.LatencyP95 = percentile(latencies, 95)
		summary.LatencyP99 = percentile(latencies, 99)
	}

	// Detect rate limiting (many 429s or sudden 403s)
	if count429, ok := summary.StatusCodes[429]; ok && count429 > 5 {
		summary.RateLimited = true
	}

	// Detect WAF (403s with specific patterns)
	if count403, ok := summary.StatusCodes[403]; ok {
		if float64(count403) > float64(summary.TotalRequests)*0.3 {
			summary.WAFDetected = true
		}
	}

	return summary
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p / 100.0) * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper || upper >= len(sorted) {
		return sorted[lower]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

func main() {
	config := Config{
		Method:   "GET",
		RPS:      10,
		Duration: 10 * time.Second,
		Workers:  50,
		Headers:  make(map[string]string),
	}

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--url":
			if i+1 < len(args) { config.URL = args[i+1]; i++ }
		case "--rps":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil { config.RPS = n }
				i++
			}
		case "--duration":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil { config.Duration = d }
				i++
			}
		case "--workers":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil { config.Workers = n }
				i++
			}
		case "--method":
			if i+1 < len(args) { config.Method = strings.ToUpper(args[i+1]); i++ }
		case "--header":
			if i+1 < len(args) {
				parts := strings.SplitN(args[i+1], ":", 2)
				if len(parts) == 2 {
					config.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
				i++
			}
		case "--body":
			if i+1 < len(args) { config.Body = args[i+1]; i++ }
		case "--json":
			config.JSON = true
		case "--verbose":
			config.Verbose = true
		}
	}

	if config.URL == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --url <target> [--rps 50] [--duration 30s] [--workers 50] [--json]\n", os.Args[0])
		os.Exit(1)
	}

	tester := NewLoadTester(config)
	ctx := context.Background()

	if !config.JSON {
		fmt.Printf("Load testing %s at %d RPS for %s with %d workers\n",
			config.URL, config.RPS, config.Duration, config.Workers)
	}

	summary := tester.Run(ctx)

	if config.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(summary)
	} else {
		fmt.Printf("\n─── Results ───\n")
		fmt.Printf("Requests:    %d total, %d success, %d errors\n", summary.TotalRequests, summary.SuccessCount, summary.ErrorCount)
		fmt.Printf("Duration:    %.1fs\n", summary.Duration)
		fmt.Printf("Throughput:  %.1f req/s\n", summary.RPS)
		fmt.Printf("Latency:\n")
		fmt.Printf("  Min:       %.1f ms\n", summary.LatencyMin)
		fmt.Printf("  Mean:      %.1f ms\n", summary.LatencyMean)
		fmt.Printf("  Median:    %.1f ms\n", summary.LatencyMedian)
		fmt.Printf("  P95:       %.1f ms\n", summary.LatencyP95)
		fmt.Printf("  P99:       %.1f ms\n", summary.LatencyP99)
		fmt.Printf("  Max:       %.1f ms\n", summary.LatencyMax)

		if len(summary.StatusCodes) > 0 {
			fmt.Printf("Status codes:\n")
			for code, count := range summary.StatusCodes {
				fmt.Printf("  %d: %d\n", code, count)
			}
		}

		if summary.RateLimited {
			fmt.Printf("\n⚠ Rate limiting detected (HTTP 429)\n")
		}
		if summary.WAFDetected {
			fmt.Printf("\n⚠ WAF/firewall detected (high 403 rate)\n")
		}
	}
}
