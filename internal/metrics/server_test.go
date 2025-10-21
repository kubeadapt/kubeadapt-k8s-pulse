package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestNewServer tests server initialization
func TestNewServer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(9090, logger)

	require.NotNil(t, server)
	assert.Equal(t, 9090, server.port)
	assert.NotNil(t, server.registry)
	assert.NotNil(t, server.logger)

	// Initial state should be live but not ready
	assert.True(t, server.isLive, "Server should be live on creation")
	assert.False(t, server.isReady, "Server should NOT be ready on creation")

	// BPF load should not have been attempted yet
	assert.False(t, server.bpfLoadSuccessful)
	assert.Equal(t, "not_attempted", server.bpfLoadError)
}

// TestHealthCheckStateTransitions tests health state management
func TestHealthCheckStateTransitions(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	// Initial state: live but not ready
	assert.True(t, server.isLive)
	assert.False(t, server.isReady)

	// Test SetReady(true)
	server.SetReady(true)
	assert.True(t, server.isReady)
	assert.False(t, server.readyAt.IsZero(), "Ready timestamp should be set")

	// Test SetReady(false)
	server.SetReady(false)
	assert.False(t, server.isReady)
}

// TestBPFLoadStatusReporting tests BPF load success/failure reporting
func TestBPFLoadStatusReporting(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	// Initial state - no load attempted
	assert.Equal(t, "not_attempted", server.bpfLoadError)
	assert.False(t, server.bpfLoadSuccessful)
	assert.False(t, server.isReady)

	// Test successful BPF load
	duration := 100 * time.Millisecond
	server.ReportBPFLoadSuccess(duration)

	assert.True(t, server.bpfLoadSuccessful, "BPF load should be marked successful")
	assert.Equal(t, "none", server.bpfLoadError, "Error should be 'none'")
	assert.True(t, server.isReady, "Server should be ready after successful BPF load")

	// Verify Prometheus metric
	statusMetric := testutil.ToFloat64(server.bpfLoadStatus)
	assert.Equal(t, 1.0, statusMetric, "BPF load status metric should be 1")

	durationMetric := testutil.ToFloat64(server.bpfLoadDuration)
	assert.Equal(t, 0.1, durationMetric, "BPF load duration should be 0.1s")

	// Test failed BPF load
	testErr := errors.New("test BPF load error")
	failDuration := 50 * time.Millisecond
	server.ReportBPFLoadFailure(testErr, failDuration)

	assert.False(t, server.bpfLoadSuccessful, "BPF load should be marked failed")
	assert.Contains(t, server.bpfLoadError, "test BPF load error", "Error message should be stored")
	assert.False(t, server.isReady, "Server should NOT be ready after BPF load failure")

	// Verify Prometheus metric updated
	statusMetric = testutil.ToFloat64(server.bpfLoadStatus)
	assert.Equal(t, 0.0, statusMetric, "BPF load status metric should be 0")

	durationMetric = testutil.ToFloat64(server.bpfLoadDuration)
	assert.Equal(t, 0.05, durationMetric, "BPF load duration should be 0.05s")
}

// TestBPFLoadAttemptsCounter tests that attempt counter increments
func TestBPFLoadAttemptsCounter(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	// Initial count should be 0
	initialCount := testutil.ToFloat64(server.bpfLoadAttempts)
	assert.Equal(t, 0.0, initialCount)

	// First success
	server.ReportBPFLoadSuccess(100 * time.Millisecond)
	count1 := testutil.ToFloat64(server.bpfLoadAttempts)
	assert.Equal(t, 1.0, count1, "Attempt counter should increment on success")

	// Second success
	server.ReportBPFLoadSuccess(100 * time.Millisecond)
	count2 := testutil.ToFloat64(server.bpfLoadAttempts)
	assert.Equal(t, 2.0, count2, "Attempt counter should increment again")

	// Failure also increments
	server.ReportBPFLoadFailure(errors.New("test"), 50*time.Millisecond)
	count3 := testutil.ToFloat64(server.bpfLoadAttempts)
	assert.Equal(t, 3.0, count3, "Attempt counter should increment on failure")
}

// TestLivenessEndpoint tests the /health/live endpoint
func TestLivenessEndpoint(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	tests := []struct {
		name           string
		isLive         bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Live server",
			isLive:         true,
			expectedStatus: http.StatusOK,
			expectedBody:   "OK\n",
		},
		{
			name:           "Not live server",
			isLive:         false,
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Not Live\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.isLive = tt.isLive

			req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
			w := httptest.NewRecorder()

			server.handleLiveness(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, tt.expectedBody, w.Body.String())
		})
	}
}

// TestReadinessEndpoint tests the /health/ready endpoint
func TestReadinessEndpoint(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	tests := []struct {
		name           string
		isReady        bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Ready server",
			isReady:        true,
			expectedStatus: http.StatusOK,
			expectedBody:   "OK\n",
		},
		{
			name:           "Not ready server",
			isReady:        false,
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Not Ready\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.isReady = tt.isReady

			req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			w := httptest.NewRecorder()

			server.handleReadiness(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, tt.expectedBody, w.Body.String())
		})
	}
}

// TestHealthEndpoint tests the /health endpoint
func TestHealthEndpoint(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	tests := []struct {
		name                string
		isLive              bool
		isReady             bool
		bpfLoadSuccessful   bool
		bpfLoadError        string
		expectedStatus      int
		expectedJSONContain string
	}{
		{
			name:                "Healthy server",
			isLive:              true,
			isReady:             true,
			bpfLoadSuccessful:   true,
			bpfLoadError:        "none",
			expectedStatus:      http.StatusOK,
			expectedJSONContain: `"status": "healthy"`,
		},
		{
			name:                "Unhealthy - not ready",
			isLive:              true,
			isReady:             false,
			bpfLoadSuccessful:   false,
			bpfLoadError:        "BPF load failed",
			expectedStatus:      http.StatusServiceUnavailable,
			expectedJSONContain: `"status": "unhealthy"`,
		},
		{
			name:                "Unhealthy - not live",
			isLive:              false,
			isReady:             true,
			bpfLoadSuccessful:   true,
			bpfLoadError:        "none",
			expectedStatus:      http.StatusServiceUnavailable,
			expectedJSONContain: `"status": "unhealthy"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.isLive = tt.isLive
			server.isReady = tt.isReady
			server.bpfLoadSuccessful = tt.bpfLoadSuccessful
			server.bpfLoadError = tt.bpfLoadError

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()

			server.handleHealth(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedJSONContain)
			assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
		})
	}
}

// TestBPFLoadErrorTruncation tests that long error messages are truncated
func TestBPFLoadErrorTruncation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	// Create a very long error message (> 256 chars)
	longError := errors.New(string(make([]byte, 300)))
	server.ReportBPFLoadFailure(longError, 100*time.Millisecond)

	// Error should be truncated to 256 chars
	assert.LessOrEqual(t, len(server.bpfLoadError), 256,
		"Error message should be truncated to 256 characters")
	assert.Contains(t, server.bpfLoadError, "...",
		"Truncated error should contain ellipsis")
}

// TestGetStatusClass tests status class helper
func TestGetStatusClass(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	// Both ready and live
	server.isReady = true
	server.isLive = true
	assert.Equal(t, "ready", server.getStatusClass())

	// Not ready
	server.isReady = false
	assert.Equal(t, "notready", server.getStatusClass())

	// Not live
	server.isReady = true
	server.isLive = false
	assert.Equal(t, "notready", server.getStatusClass())
}

// TestGetStatusText tests status text helper
func TestGetStatusText(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	// Both ready and live
	server.isReady = true
	server.isLive = true
	assert.Equal(t, "HEALTHY", server.getStatusText())

	// Live but not ready (starting)
	server.isReady = false
	server.isLive = true
	assert.Equal(t, "STARTING", server.getStatusText())

	// Not live
	server.isLive = false
	assert.Equal(t, "UNHEALTHY", server.getStatusText())
}

// TestRegistry tests that Prometheus registry is accessible
func TestRegistry(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	registry := server.Registry()
	require.NotNil(t, registry)

	// Verify it's a valid registry by gathering metrics
	mfs, err := registry.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs, "Registry should have some metrics")

	// Look for our BPF load metrics
	foundBPFStatus := false
	for _, mf := range mfs {
		if mf.GetName() == "kubeadapt_bpf_load_status" {
			foundBPFStatus = true
			break
		}
	}
	assert.True(t, foundBPFStatus, "BPF load status metric should be registered")
}

// TestMetricsRegistration tests that standard metrics are registered
func TestMetricsRegistration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	mfs, err := server.registry.Gather()
	require.NoError(t, err)

	// Collect metric names
	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	// Verify our custom metrics are registered
	expectedMetrics := []string{
		"kubeadapt_bpf_load_status",
		"kubeadapt_bpf_load_attempts_total",
		"kubeadapt_bpf_load_duration_seconds",
	}

	for _, name := range expectedMetrics {
		assert.True(t, metricNames[name],
			"Expected metric %s to be registered", name)
	}

	// Verify Go metrics are registered
	assert.True(t, metricNames["go_goroutines"],
		"Go runtime metrics should be registered")
}

// TestMultipleBPFLoadReports tests multiple BPF load reports
func TestMultipleBPFLoadReports(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	// First load fails
	server.ReportBPFLoadFailure(errors.New("first error"), 50*time.Millisecond)
	assert.False(t, server.isReady)
	assert.Equal(t, "first error", server.bpfLoadError)

	// Second load succeeds
	server.ReportBPFLoadSuccess(100 * time.Millisecond)
	assert.True(t, server.isReady)
	assert.Equal(t, "none", server.bpfLoadError)

	// Third load fails again
	server.ReportBPFLoadFailure(errors.New("second error"), 75*time.Millisecond)
	assert.False(t, server.isReady)
	assert.Equal(t, "second error", server.bpfLoadError)

	// Verify attempt counter
	attempts := testutil.ToFloat64(server.bpfLoadAttempts)
	assert.Equal(t, 3.0, attempts, "Should have 3 total attempts")
}

// TestPromLogger tests the Prometheus logger adapter
func TestPromLogger(t *testing.T) {
	logger := zaptest.NewLogger(t)
	promLogger := NewPromLogger(logger)

	require.NotNil(t, promLogger)
	require.NotNil(t, promLogger.logger)

	// Test that Println doesn't panic
	require.NotPanics(t, func() {
		promLogger.Println("test message")
	})
}

// TestNilLogger tests that nil logger is handled
func TestNilLogger(t *testing.T) {
	server := NewServer(8080, nil)
	require.NotNil(t, server)
	require.NotNil(t, server.logger, "Nil logger should be replaced with nop logger")
}

// TestServerUptimeTracking tests that uptime is tracked
func TestServerUptimeTracking(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewServer(8080, logger)

	startTime := server.startedAt
	require.False(t, startTime.IsZero(), "Start time should be set")

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Check health endpoint includes uptime
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	server.handleHealth(w, req)

	body := w.Body.String()
	assert.Contains(t, body, "uptime_seconds")
	assert.Contains(t, body, "started_at")
}

// BenchmarkHealthEndpoint benchmarks the health endpoint
func BenchmarkHealthEndpoint(b *testing.B) {
	logger := zaptest.NewLogger(b)
	server := NewServer(8080, logger)
	server.isLive = true
	server.isReady = true

	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		server.handleHealth(w, req)
	}
}

// BenchmarkBPFLoadStatusMetric benchmarks BPF load status metric access
func BenchmarkBPFLoadStatusMetric(b *testing.B) {
	logger := zaptest.NewLogger(b)
	server := NewServer(8080, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = testutil.ToFloat64(server.bpfLoadStatus)
	}
}
