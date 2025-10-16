package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Server serves Prometheus metrics via HTTP
type Server struct {
	port     int
	registry *prometheus.Registry
	server   *http.Server
	logger   *zap.Logger

	// Health check state
	isReady   bool
	isLive    bool
	readyAt   time.Time
	startedAt time.Time
}

// NewServer creates a new metrics server
func NewServer(port int, logger *zap.Logger) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}

	registry := prometheus.NewRegistry()

	// Register standard Go metrics using collectors package
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return &Server{
		port:      port,
		registry:  registry,
		logger:    logger,
		isLive:    true,
		startedAt: time.Now(),
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle("/metrics", promhttp.HandlerFor(
		s.registry,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
			Registry:          s.registry,
			ErrorLog:          NewPromLogger(s.logger),
		},
	))

	// Health endpoints
	mux.HandleFunc("/health/live", s.handleLiveness)
	mux.HandleFunc("/health/ready", s.handleReadiness)
	mux.HandleFunc("/health", s.handleHealth)

	// Root endpoint
	mux.HandleFunc("/", s.handleRoot)

	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.logger.Info("Starting metrics server",
		zap.Int("port", s.port),
	)

	// Mark as ready after a brief delay
	go func() {
		time.Sleep(2 * time.Second)
		s.SetReady(true)
	}()

	err := s.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("metrics server error: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down metrics server")
	s.isReady = false
	s.isLive = false

	if s.server != nil {
		return s.server.Shutdown(ctx)
	}

	return nil
}

// Registry returns the Prometheus registry
func (s *Server) Registry() *prometheus.Registry {
	return s.registry
}

// SetReady sets the ready state
func (s *Server) SetReady(ready bool) {
	s.isReady = ready
	if ready {
		s.readyAt = time.Now()
		s.logger.Info("Metrics server marked as ready")
	}
}

// handleRoot handles the root endpoint
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>KubeAdapt eBPF Agent</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; background: ***REMOVED***f5f5f5; }
        h1 { color: ***REMOVED***333; }
        .info { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }
        .metric { margin: 10px 0; }
        .label { font-weight: 600; color: ***REMOVED***666; }
        a { color: ***REMOVED***007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .status.ready { background: ***REMOVED***d4edda; color: ***REMOVED***155724; }
        .status.notready { background: ***REMOVED***f8d7da; color: ***REMOVED***721c24; }
    </style>
</head>
<body>
    <h1>🚀 KubeAdapt eBPF Network Metrics Agent</h1>

    <div class="info">
        <h2>Status</h2>
        <div class="metric">
            <span class="label">Health:</span>
            <span class="status %s">%s</span>
        </div>
        <div class="metric">
            <span class="label">Started:</span> %s
        </div>
        <div class="metric">
            <span class="label">Uptime:</span> %s
        </div>
    </div>

    <div class="info">
        <h2>Endpoints</h2>
        <div class="metric">
            <a href="/metrics">📊 /metrics</a> - Prometheus metrics
        </div>
        <div class="metric">
            <a href="/health">🏥 /health</a> - Combined health status
        </div>
        <div class="metric">
            <a href="/health/live">💓 /health/live</a> - Liveness probe
        </div>
        <div class="metric">
            <a href="/health/ready">✅ /health/ready</a> - Readiness probe
        </div>
    </div>

    <div class="info">
        <h2>About</h2>
        <p>This agent provides true container-level network metrics by leveraging eBPF to intercept network syscalls at the kernel level.</p>
        <p>Unlike standard Kubernetes metrics that are aggregated at the pod level, this agent tracks individual container network usage.</p>
    </div>
</body>
</html>`,
		s.getStatusClass(),
		s.getStatusText(),
		s.startedAt.Format(time.RFC3339),
		time.Since(s.startedAt).Round(time.Second).String(),
	)
}

// handleLiveness handles the liveness probe
func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	if s.isLive {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK\n")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "Not Live\n")
	}
}

// handleReadiness handles the readiness probe
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if s.isReady {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK\n")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "Not Ready\n")
	}
}

// handleHealth handles the combined health check
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := "healthy"
	statusCode := http.StatusOK

	if !s.isLive || !s.isReady {
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, `{
  "status": "%s",
  "live": %t,
  "ready": %t,
  "uptime_seconds": %.0f,
  "started_at": "%s"
}
`, status, s.isLive, s.isReady, time.Since(s.startedAt).Seconds(), s.startedAt.Format(time.RFC3339))
}

// getStatusClass returns CSS class for status
func (s *Server) getStatusClass() string {
	if s.isReady && s.isLive {
		return "ready"
	}
	return "notready"
}

// getStatusText returns status text
func (s *Server) getStatusText() string {
	if s.isReady && s.isLive {
		return "HEALTHY"
	}
	if s.isLive {
		return "STARTING"
	}
	return "UNHEALTHY"
}

// PromLogger adapts zap logger for Prometheus
type PromLogger struct {
	logger *zap.Logger
}

// NewPromLogger creates a new Prometheus logger adapter
func NewPromLogger(logger *zap.Logger) *PromLogger {
	return &PromLogger{logger: logger}
}

// Println implements promhttp.Logger
func (l *PromLogger) Println(v ...interface{}) {
	l.logger.Error(fmt.Sprint(v...))
}
