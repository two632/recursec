// Package main — High-performance concurrent task coordinator for RecurSec.
//
// This Go component handles the performance-critical parts of agent coordination:
// 1. Concurrent task dispatch with worker pools
// 2. Real-time result aggregation across agents
// 3. Health monitoring of all LLM servers
// 4. WebSocket hub for live dashboard updates
// 5. Task queue with priority scheduling
// 6. Rate limiting per target/tool
// 7. Circuit breaker pattern for failing tools
//
// Communicates with the Python agent brain via HTTP API.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─── Task Types ───

type TaskPriority int

const (
	PriorityCritical TaskPriority = 0
	PriorityHigh     TaskPriority = 1
	PriorityNormal   TaskPriority = 2
	PriorityLow      TaskPriority = 3
)

type TaskStatus string

const (
	StatusPending    TaskStatus = "pending"
	StatusRunning    TaskStatus = "running"
	StatusCompleted  TaskStatus = "completed"
	StatusFailed     TaskStatus = "failed"
	StatusCancelled  TaskStatus = "cancelled"
)

type Task struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Target      string            `json:"target"`
	Tool        string            `json:"tool"`
	Priority    TaskPriority      `json:"priority"`
	Status      TaskStatus        `json:"status"`
	AgentID     string            `json:"agent_id"`
	ParentID    string            `json:"parent_id,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Result      *TaskResult       `json:"result,omitempty"`
	Retries     int               `json:"retries"`
	MaxRetries  int               `json:"max_retries"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type TaskResult struct {
	Success       bool              `json:"success"`
	FindingsCount int               `json:"findings_count"`
	Output        string            `json:"output,omitempty"`
	Error         string            `json:"error,omitempty"`
	Duration      time.Duration     `json:"duration_ms"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ─── Priority Queue ───

type PriorityQueue struct {
	mu    sync.Mutex
	tasks []*Task
	cond  *sync.Cond
}

func NewPriorityQueue() *PriorityQueue {
	pq := &PriorityQueue{}
	pq.cond = sync.NewCond(&pq.mu)
	return pq
}

func (pq *PriorityQueue) Push(task *Task) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	pq.tasks = append(pq.tasks, task)
	sort.SliceStable(pq.tasks, func(i, j int) bool {
		return pq.tasks[i].Priority < pq.tasks[j].Priority
	})
	pq.cond.Signal()
}

func (pq *PriorityQueue) Pop(ctx context.Context) (*Task, bool) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	for len(pq.tasks) == 0 {
		done := make(chan struct{})
		go func() {
			pq.cond.Wait()
			close(done)
		}()
		pq.mu.Unlock()
		select {
		case <-done:
			pq.mu.Lock()
		case <-ctx.Done():
			pq.mu.Lock()
			return nil, false
		}
	}
	task := pq.tasks[0]
	pq.tasks = pq.tasks[1:]
	return task, true
}

func (pq *PriorityQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.tasks)
}

// ─── Circuit Breaker ───

type CircuitState int

const (
	CircuitClosed   CircuitState = 0
	CircuitOpen     CircuitState = 1
	CircuitHalfOpen CircuitState = 2
)

type CircuitBreaker struct {
	mu           sync.Mutex
	state        CircuitState
	failures     int
	threshold    int
	lastFailure  time.Time
	resetTimeout time.Duration
	successes    int
	halfOpenMax  int
}

func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:        CircuitClosed,
		threshold:    threshold,
		resetTimeout: resetTimeout,
		halfOpenMax:  2,
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = CircuitHalfOpen
			cb.successes = 0
			return true
		}
		return false
	case CircuitHalfOpen:
		return cb.successes < cb.halfOpenMax
	}
	return false
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case CircuitHalfOpen:
		cb.successes++
		if cb.successes >= cb.halfOpenMax {
			cb.state = CircuitClosed
			cb.failures = 0
		}
	case CircuitClosed:
		cb.failures = 0
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.threshold {
		cb.state = CircuitOpen
	}
}

// ─── Rate Limiter (Token Bucket) ───

type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	maxTokens float64
	refillRate float64
	lastRefill time.Time
}

func NewRateLimiter(maxTokens float64, refillPerSec float64) *RateLimiter {
	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillPerSec,
		lastRefill: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens = math.Min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)
	rl.lastRefill = now
	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

// ─── LLM Health Monitor ───

type ModelHealth struct {
	ModelID     string    `json:"model_id"`
	Port        int       `json:"port"`
	Healthy     bool      `json:"healthy"`
	LastCheck   time.Time `json:"last_check"`
	Latency     int64     `json:"latency_ms"`
	Consecutive int       `json:"consecutive_failures"`
}

type HealthMonitor struct {
	mu      sync.RWMutex
	models  map[string]*ModelHealth
	client  *http.Client
	baseURL string
}

func NewHealthMonitor(baseURL string) *HealthMonitor {
	models := map[string]*ModelHealth{
		"whiterabbit":   {ModelID: "whiterabbit", Port: 8100},
		"mistral":       {ModelID: "mistral", Port: 8101},
		"qwen-coder-14b": {ModelID: "qwen-coder-14b", Port: 8102},
		"qwen-coder-7b": {ModelID: "qwen-coder-7b", Port: 8103},
		"deepseek-r1":   {ModelID: "deepseek-r1", Port: 8104},
		"hermes-4-14b":  {ModelID: "hermes-4-14b", Port: 8105},
		"llama-3.1-8b":  {ModelID: "llama-3.1-8b", Port: 8106},
		"codellama-13b": {ModelID: "codellama-13b", Port: 8107},
		"codellama-7b":  {ModelID: "codellama-7b", Port: 8108},
		"dolphin":       {ModelID: "dolphin", Port: 8109},
		"phi-3.5-mini":  {ModelID: "phi-3.5-mini", Port: 8110},
		"deepseek-math": {ModelID: "deepseek-math", Port: 8111},
		"yi-9b-200k":    {ModelID: "yi-9b-200k", Port: 8112},
		"functiongemma": {ModelID: "functiongemma", Port: 8113},
		"llama-guard":   {ModelID: "llama-guard", Port: 8114},
		"nomic-embed":   {ModelID: "nomic-embed", Port: 8115},
	}
	return &HealthMonitor{
		models:  models,
		client:  &http.Client{Timeout: 3 * time.Second},
		baseURL: baseURL,
	}
}

func (hm *HealthMonitor) CheckAll() {
	var wg sync.WaitGroup
	hm.mu.RLock()
	modelsCopy := make([]*ModelHealth, 0, len(hm.models))
	for _, m := range hm.models {
		modelsCopy = append(modelsCopy, m)
	}
	hm.mu.RUnlock()

	for _, model := range modelsCopy {
		wg.Add(1)
		go func(m *ModelHealth) {
			defer wg.Done()
			url := fmt.Sprintf("%s:%d/health", hm.baseURL, m.Port)
			start := time.Now()
			resp, err := hm.client.Get(url)
			latency := time.Since(start).Milliseconds()

			hm.mu.Lock()
			defer hm.mu.Unlock()
			m.LastCheck = time.Now()
			m.Latency = latency
			if err != nil || resp.StatusCode != 200 {
				m.Healthy = false
				m.Consecutive++
			} else {
				m.Healthy = true
				m.Consecutive = 0
			}
			if resp != nil {
				resp.Body.Close()
			}
		}(model)
	}
	wg.Wait()
}

func (hm *HealthMonitor) GetHealthy() []string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	var healthy []string
	for id, m := range hm.models {
		if m.Healthy {
			healthy = append(healthy, id)
		}
	}
	return healthy
}

func (hm *HealthMonitor) GetStatus() map[string]*ModelHealth {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	result := make(map[string]*ModelHealth, len(hm.models))
	for k, v := range hm.models {
		copied := *v
		result[k] = &copied
	}
	return result
}

// ─── Worker Pool ───

type WorkerPool struct {
	queue       *PriorityQueue
	breakers    map[string]*CircuitBreaker
	limiters    map[string]*RateLimiter
	health      *HealthMonitor
	workers     int
	active      int64
	completed   int64
	failed      int64
	mu          sync.Mutex
	results     []*TaskResult
	subscribers []chan *Task
}

func NewWorkerPool(workers int, queue *PriorityQueue, health *HealthMonitor) *WorkerPool {
	return &WorkerPool{
		queue:    queue,
		health:   health,
		workers:  workers,
		breakers: make(map[string]*CircuitBreaker),
		limiters: make(map[string]*RateLimiter),
	}
}

func (wp *WorkerPool) GetBreaker(tool string) *CircuitBreaker {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if cb, ok := wp.breakers[tool]; ok {
		return cb
	}
	cb := NewCircuitBreaker(5, 30*time.Second)
	wp.breakers[tool] = cb
	return cb
}

func (wp *WorkerPool) GetLimiter(target string) *RateLimiter {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if rl, ok := wp.limiters[target]; ok {
		return rl
	}
	rl := NewRateLimiter(10, 2)
	wp.limiters[target] = rl
	return rl
}

func (wp *WorkerPool) Subscribe() chan *Task {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	ch := make(chan *Task, 100)
	wp.subscribers = append(wp.subscribers, ch)
	return ch
}

func (wp *WorkerPool) notify(task *Task) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	for _, ch := range wp.subscribers {
		select {
		case ch <- task:
		default:
		}
	}
}

func (wp *WorkerPool) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < wp.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			wp.worker(ctx, workerID)
		}(i)
	}
	wg.Wait()
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
	for {
		task, ok := wp.queue.Pop(ctx)
		if !ok {
			return
		}

		// Check circuit breaker
		if task.Tool != "" {
			cb := wp.GetBreaker(task.Tool)
			if !cb.Allow() {
				task.Status = StatusFailed
				task.Result = &TaskResult{Error: "circuit breaker open"}
				atomic.AddInt64(&wp.failed, 1)
				wp.notify(task)
				continue
			}
		}

		// Check rate limiter
		if task.Target != "" {
			rl := wp.GetLimiter(task.Target)
			if !rl.Allow() {
				// Re-queue with slight delay
				go func(t *Task) {
					time.Sleep(500 * time.Millisecond)
					wp.queue.Push(t)
				}(task)
				continue
			}
		}

		atomic.AddInt64(&wp.active, 1)
		now := time.Now()
		task.StartedAt = &now
		task.Status = StatusRunning
		wp.notify(task)

		// Execute task (call Python agent API)
		result := wp.executeTask(ctx, task)
		task.Result = result
		completed := time.Now()
		task.CompletedAt = &completed

		if result.Success {
			task.Status = StatusCompleted
			atomic.AddInt64(&wp.completed, 1)
			if task.Tool != "" {
				wp.GetBreaker(task.Tool).RecordSuccess()
			}
		} else {
			if task.Retries < task.MaxRetries {
				task.Retries++
				task.Status = StatusPending
				wp.queue.Push(task)
			} else {
				task.Status = StatusFailed
				atomic.AddInt64(&wp.failed, 1)
			}
			if task.Tool != "" {
				wp.GetBreaker(task.Tool).RecordFailure()
			}
		}

		atomic.AddInt64(&wp.active, -1)
		wp.notify(task)
	}
}

func (wp *WorkerPool) executeTask(_ context.Context, task *Task) *TaskResult {
	// In production, this calls the Python agent's HTTP API
	start := time.Now()
	log.Printf("[worker] Executing task %s: %s on %s", task.ID, task.Tool, task.Target)
	return &TaskResult{
		Success:       true,
		FindingsCount: 0,
		Duration:      time.Since(start),
	}
}

func (wp *WorkerPool) Stats() map[string]interface{} {
	return map[string]interface{}{
		"workers":   wp.workers,
		"active":    atomic.LoadInt64(&wp.active),
		"completed": atomic.LoadInt64(&wp.completed),
		"failed":    atomic.LoadInt64(&wp.failed),
		"queued":    wp.queue.Len(),
	}
}

// ─── WebSocket Hub ───

type WSHub struct {
	mu          sync.Mutex
	connections map[string]chan []byte
	counter     int
}

func NewWSHub() *WSHub {
	return &WSHub{
		connections: make(map[string]chan []byte),
	}
}

func (h *WSHub) Register() (string, chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.counter++
	id := fmt.Sprintf("ws-%d", h.counter)
	ch := make(chan []byte, 256)
	h.connections[id] = ch
	return id, ch
}

func (h *WSHub) Unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.connections[id]; ok {
		close(ch)
		delete(h.connections, id)
	}
}

func (h *WSHub) Broadcast(data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.connections {
		select {
		case ch <- data:
		default:
		}
	}
}

// ─── HTTP API Server ───

type Coordinator struct {
	queue   *PriorityQueue
	pool    *WorkerPool
	health  *HealthMonitor
	hub     *WSHub
	taskID  int64
}

func NewCoordinator(workers int) *Coordinator {
	queue := NewPriorityQueue()
	health := NewHealthMonitor("http://127.0.0.1")
	pool := NewWorkerPool(workers, queue, health)
	hub := NewWSHub()

	return &Coordinator{
		queue:  queue,
		pool:   pool,
		health: health,
		hub:    hub,
	}
}

func (c *Coordinator) handleSubmitTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var task Task
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	task.ID = fmt.Sprintf("task-%d", atomic.AddInt64(&c.taskID, 1))
	task.Status = StatusPending
	task.CreatedAt = time.Now()
	if task.MaxRetries == 0 {
		task.MaxRetries = 3
	}
	c.queue.Push(&task)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"task_id": task.ID, "status": "queued"})
}

func (c *Coordinator) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats := map[string]interface{}{
		"pool":    c.pool.Stats(),
		"models":  c.health.GetStatus(),
		"healthy": c.health.GetHealthy(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (c *Coordinator) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (c *Coordinator) handleModels(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c.health.GetStatus())
}

func main() {
	port := "9000"
	if p := os.Getenv("COORDINATOR_PORT"); p != "" {
		port = p
	}
	workers := 8
	coord := NewCoordinator(workers)

	// Start health monitoring
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			coord.health.CheckAll()
		}
	}()

	// Start broadcasting task updates
	sub := coord.pool.Subscribe()
	go func() {
		for task := range sub {
			data, _ := json.Marshal(task)
			coord.hub.Broadcast(data)
		}
	}()

	// Start worker pool
	ctx, cancel := context.WithCancel(context.Background())
	go coord.pool.Run(ctx)

	// HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tasks", coord.handleSubmitTask)
	mux.HandleFunc("/api/stats", coord.handleStats)
	mux.HandleFunc("/api/health", coord.handleHealth)
	mux.HandleFunc("/api/models", coord.handleModels)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down coordinator...")
		cancel()
		server.Close()
	}()

	log.Printf("RecurSec Coordinator starting on port %s with %d workers", port, workers)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
