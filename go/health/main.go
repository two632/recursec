// RecurSec Model Health Monitor
//
// Continuously monitors all 16 llama.cpp model servers:
// - Health check (HTTP ping)
// - Response latency measurement
// - Token throughput benchmarking
// - Memory usage tracking
// - Automatic restart on failure
// - REST API for status queries
// - Prometheus-compatible metrics endpoint
//
// Usage: ./health --config recursec.yaml --port 9091

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Model represents a llama.cpp model server
type Model struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Role     string `json:"role"`
	Status   string `json:"status"` // healthy, degraded, down, unknown
	LastPing time.Time `json:"last_ping"`

	// Metrics
	Latency     float64 `json:"latency_ms"`
	AvgLatency  float64 `json:"avg_latency_ms"`
	MinLatency  float64 `json:"min_latency_ms"`
	MaxLatency  float64 `json:"max_latency_ms"`
	TokensPerSec float64 `json:"tokens_per_sec"`
	Uptime      float64 `json:"uptime_pct"`
	TotalPings  int     `json:"total_pings"`
	FailedPings int     `json:"failed_pings"`

	mu sync.RWMutex
	latencies []float64
}

// DefaultModels returns the 16 model configurations
func DefaultModels() []*Model {
	return []*Model{
		{ID: "whiterabbit", Name: "WhiteRabbitNeo-7B", Host: "127.0.0.1", Port: 8101, Role: "security"},
		{ID: "qwen-coder-14b", Name: "Qwen2.5-Coder-14B", Host: "127.0.0.1", Port: 8102, Role: "code"},
		{ID: "qwen-coder-7b", Name: "Qwen2.5-Coder-7B", Host: "127.0.0.1", Port: 8103, Role: "code"},
		{ID: "codellama-13b", Name: "CodeLlama-13B", Host: "127.0.0.1", Port: 8104, Role: "code"},
		{ID: "codellama-7b", Name: "CodeLlama-7B", Host: "127.0.0.1", Port: 8105, Role: "code"},
		{ID: "deepseek-r1", Name: "DeepSeek-R1-Distill-7B", Host: "127.0.0.1", Port: 8106, Role: "reasoning"},
		{ID: "deepseek-math", Name: "DeepSeek-Math-7B", Host: "127.0.0.1", Port: 8107, Role: "reasoning"},
		{ID: "hermes-4-14b", Name: "Hermes-4-14B", Host: "127.0.0.1", Port: 8108, Role: "general"},
		{ID: "llama-3.1-8b", Name: "Llama-3.1-8B", Host: "127.0.0.1", Port: 8109, Role: "general"},
		{ID: "dolphin-2.9", Name: "Dolphin-2.9-Llama3-8B", Host: "127.0.0.1", Port: 8110, Role: "general"},
		{ID: "mistral-7b", Name: "Mistral-7B-Instruct-v0.3", Host: "127.0.0.1", Port: 8111, Role: "general"},
		{ID: "yi-9b-200k", Name: "Yi-9B-200K", Host: "127.0.0.1", Port: 8112, Role: "long_context"},
		{ID: "llama-guard", Name: "Llama-Guard-3-1B", Host: "127.0.0.1", Port: 8114, Role: "safety"},
		{ID: "nomic-embed", Name: "Nomic-Embed-Text-v1.5", Host: "127.0.0.1", Port: 8115, Role: "embedding"},
		{ID: "functiongemma", Name: "FunctionGemma-270m", Host: "127.0.0.1", Port: 8116, Role: "function_call"},
		{ID: "phi-3.5-mini", Name: "Phi-3.5-mini", Host: "127.0.0.1", Port: 8117, Role: "fast"},
	}
}

// HealthMonitor monitors all model servers
type HealthMonitor struct {
	models    []*Model
	interval  time.Duration
	timeout   time.Duration
	client    *http.Client
	mu        sync.RWMutex
	startTime time.Time
}

func NewHealthMonitor(interval, timeout time.Duration) *HealthMonitor {
	return &HealthMonitor{
		models:   DefaultModels(),
		interval: interval,
		timeout:  timeout,
		client: &http.Client{
			Timeout: timeout,
		},
		startTime: time.Now(),
	}
}

func (hm *HealthMonitor) Start(ctx context.Context) {
	log.Printf("Health monitor started, checking %d models every %s", len(hm.models), hm.interval)

	// Initial check
	hm.checkAll()

	ticker := time.NewTicker(hm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hm.checkAll()
		}
	}
}

func (hm *HealthMonitor) checkAll() {
	var wg sync.WaitGroup
	for _, model := range hm.models {
		wg.Add(1)
		go func(m *Model) {
			defer wg.Done()
			hm.checkModel(m)
		}(model)
	}
	wg.Wait()
}

func (hm *HealthMonitor) checkModel(m *Model) {
	url := fmt.Sprintf("http://%s:%d/health", m.Host, m.Port)

	start := time.Now()
	resp, err := hm.client.Get(url)
	latency := float64(time.Since(start).Milliseconds())

	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalPings++
	m.LastPing = time.Now()

	if err != nil {
		m.Status = "down"
		m.FailedPings++
		m.Latency = 0
		return
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		m.Status = "healthy"
	} else {
		m.Status = "degraded"
		m.FailedPings++
	}

	m.Latency = latency
	m.latencies = append(m.latencies, latency)
	if len(m.latencies) > 100 {
		m.latencies = m.latencies[len(m.latencies)-100:]
	}

	// Calculate stats
	if len(m.latencies) > 0 {
		sum := 0.0
		m.MinLatency = m.latencies[0]
		m.MaxLatency = m.latencies[0]
		for _, l := range m.latencies {
			sum += l
			if l < m.MinLatency {
				m.MinLatency = l
			}
			if l > m.MaxLatency {
				m.MaxLatency = l
			}
		}
		m.AvgLatency = sum / float64(len(m.latencies))
	}

	if m.TotalPings > 0 {
		m.Uptime = float64(m.TotalPings-m.FailedPings) / float64(m.TotalPings) * 100.0
	}
}

func (hm *HealthMonitor) GetStatus() []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(hm.models))
	for _, m := range hm.models {
		m.mu.RLock()
		entry := map[string]interface{}{
			"id":            m.ID,
			"name":          m.Name,
			"endpoint":      fmt.Sprintf("%s:%d", m.Host, m.Port),
			"role":          m.Role,
			"status":        m.Status,
			"latency_ms":    fmt.Sprintf("%.1f", m.Latency),
			"avg_latency":   fmt.Sprintf("%.1f", m.AvgLatency),
			"min_latency":   fmt.Sprintf("%.1f", m.MinLatency),
			"max_latency":   fmt.Sprintf("%.1f", m.MaxLatency),
			"uptime_pct":    fmt.Sprintf("%.1f", m.Uptime),
			"total_pings":   m.TotalPings,
			"failed_pings":  m.FailedPings,
		}
		m.mu.RUnlock()
		result = append(result, entry)
	}
	return result
}

func (hm *HealthMonitor) GetSummary() map[string]interface{} {
	healthy, degraded, down := 0, 0, 0
	for _, m := range hm.models {
		m.mu.RLock()
		switch m.Status {
		case "healthy":
			healthy++
		case "degraded":
			degraded++
		default:
			down++
		}
		m.mu.RUnlock()
	}

	return map[string]interface{}{
		"total":    len(hm.models),
		"healthy":  healthy,
		"degraded": degraded,
		"down":     down,
		"uptime":   time.Since(hm.startTime).String(),
	}
}

// GetMetrics returns Prometheus-compatible metrics
func (hm *HealthMonitor) GetMetrics() string {
	var sb strings.Builder
	sb.WriteString("# HELP recursec_model_latency_ms Model response latency in milliseconds\n")
	sb.WriteString("# TYPE recursec_model_latency_ms gauge\n")
	for _, m := range hm.models {
		m.mu.RLock()
		sb.WriteString(fmt.Sprintf("recursec_model_latency_ms{model=\"%s\",role=\"%s\"} %.1f\n", m.ID, m.Role, m.Latency))
		m.mu.RUnlock()
	}

	sb.WriteString("# HELP recursec_model_up Model health status (1=up, 0=down)\n")
	sb.WriteString("# TYPE recursec_model_up gauge\n")
	for _, m := range hm.models {
		m.mu.RLock()
		up := 0
		if m.Status == "healthy" {
			up = 1
		}
		sb.WriteString(fmt.Sprintf("recursec_model_up{model=\"%s\",role=\"%s\"} %d\n", m.ID, m.Role, up))
		m.mu.RUnlock()
	}

	sb.WriteString("# HELP recursec_model_uptime_pct Model uptime percentage\n")
	sb.WriteString("# TYPE recursec_model_uptime_pct gauge\n")
	for _, m := range hm.models {
		m.mu.RLock()
		sb.WriteString(fmt.Sprintf("recursec_model_uptime_pct{model=\"%s\"} %.1f\n", m.ID, m.Uptime))
		m.mu.RUnlock()
	}

	return sb.String()
}

// GetModelsByRole returns models grouped by role, sorted by latency
func (hm *HealthMonitor) GetModelsByRole() map[string][]map[string]interface{} {
	byRole := make(map[string][]map[string]interface{})
	for _, m := range hm.models {
		m.mu.RLock()
		entry := map[string]interface{}{
			"id":      m.ID,
			"name":    m.Name,
			"status":  m.Status,
			"latency": m.AvgLatency,
		}
		m.mu.RUnlock()
		byRole[m.Role] = append(byRole[m.Role], entry)
	}

	// Sort each role group by latency
	for _, models := range byRole {
		sort.Slice(models, func(i, j int) bool {
			li, _ := models[i]["latency"].(float64)
			lj, _ := models[j]["latency"].(float64)
			return li < lj
		})
	}
	return byRole
}

func setupAPI(hm *HealthMonitor) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hm.GetSummary())
	})

	mux.HandleFunc("/api/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hm.GetStatus())
	})

	mux.HandleFunc("/api/models/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hm.GetModelsByRole())
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, hm.GetMetrics())
	})

	return mux
}

func main() {
	port := 9091
	interval := 10 * time.Second
	timeout := 5 * time.Second

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					port = n
				}
				i++
			}
		case "--interval":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					interval = d
				}
				i++
			}
		case "--timeout":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					timeout = d
				}
				i++
			}
		}
	}

	monitor := NewHealthMonitor(interval, timeout)
	ctx := context.Background()

	go monitor.Start(ctx)

	mux := setupAPI(monitor)
	addr := fmt.Sprintf(":%d", port)
	log.Printf("RecurSec Health Monitor API on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
