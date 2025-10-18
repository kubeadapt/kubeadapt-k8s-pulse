package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
)

// PrometheusClient represents a Prometheus API client for testing
type PrometheusClient struct {
	t       *testing.T
	baseURL string
	client  *http.Client
}

// NewPrometheusClient creates a new Prometheus client
func NewPrometheusClient(t *testing.T, baseURL string) *PrometheusClient {
	return &PrometheusClient{
		t:       t,
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// PrometheusQueryResult represents a Prometheus query response
type PrometheusQueryResult struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []interface{}     `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// Query executes a PromQL query
func (p *PrometheusClient) Query(ctx context.Context, query string) (*PrometheusQueryResult, error) {
	p.t.Logf("Executing Prometheus query: %s", query)

	u, err := url.Parse(fmt.Sprintf("%s/api/v1/query", p.baseURL))
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	q := u.Query()
	q.Set("query", query)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.t.Logf("Error closing response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result PrometheusQueryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w, body: %s", err, string(body))
	}

	if result.Status != "success" {
		return nil, fmt.Errorf("query failed with status: %s", result.Status)
	}

	p.t.Logf("Query returned %d results", len(result.Data.Result))
	return &result, nil
}

// WaitForMetric waits for a metric to appear with specific labels using test.Eventually pattern
func (p *PrometheusClient) WaitForMetric(ctx context.Context, metricName string, labels map[string]string, minValue float64) error {
	p.t.Logf("Waiting for metric %s with labels %v to have value >= %f", metricName, labels, minValue)

	// Build label selector
	labelSelectors := make([]string, 0, len(labels))
	for k, v := range labels {
		labelSelectors = append(labelSelectors, fmt.Sprintf("%s=%q", k, v))
	}

	query := metricName
	if len(labelSelectors) > 0 {
		query = fmt.Sprintf("%s{%s}", metricName, strings.Join(labelSelectors, ","))
	}

	// Use test.Eventually pattern from NetObserv for cleaner retry logic
	test.Eventually(p.t, 2*time.Minute, func(t require.TestingT) {
		result, err := p.Query(ctx, query)
		if err != nil {
			require.NoErrorf(t, err, "Failed to query Prometheus for metric %s", metricName)
			return
		}

		if len(result.Data.Result) == 0 {
			require.Failf(t, "Metric not found", "Metric %s not found in Prometheus", metricName)
			return
		}

		// Check if value meets minimum
		for _, r := range result.Data.Result {
			if len(r.Value) >= 2 {
				if valueStr, ok := r.Value[1].(string); ok {
					var value float64
					_, _ = fmt.Sscanf(valueStr, "%f", &value)

					if value >= minValue {
						p.t.Logf("✓ Metric %s found with value %f >= %f", metricName, value, minValue)
						return // Success!
					}

					require.Failf(t, "Metric value too low",
						"Metric %s found but value %f < %f", metricName, value, minValue)
					return
				}
			}
		}

		require.Failf(t, "Invalid metric format",
			"Metric %s has invalid value format", metricName)
	}, test.Interval(5*time.Second))

	return nil
}

// GetMetricValue gets the current value of a metric with specific labels
func (p *PrometheusClient) GetMetricValue(ctx context.Context, metricName string, labels map[string]string) (float64, error) {
	// Build label selector
	labelSelectors := make([]string, 0, len(labels))
	for k, v := range labels {
		labelSelectors = append(labelSelectors, fmt.Sprintf("%s=%q", k, v))
	}

	query := metricName
	if len(labelSelectors) > 0 {
		query = fmt.Sprintf("%s{%s}", metricName, strings.Join(labelSelectors, ","))
	}

	result, err := p.Query(ctx, query)
	if err != nil {
		return 0, err
	}

	if len(result.Data.Result) == 0 {
		return 0, fmt.Errorf("metric not found")
	}

	// Get first result value
	if len(result.Data.Result[0].Value) >= 2 {
		if valueStr, ok := result.Data.Result[0].Value[1].(string); ok {
			var value float64
			_, _ = fmt.Sscanf(valueStr, "%f", &value)
			return value, nil
		}
	}

	return 0, fmt.Errorf("invalid metric value format")
}

// WaitForReady waits for Prometheus to become ready using test.Eventually pattern
func (p *PrometheusClient) WaitForReady(ctx context.Context) error {
	p.t.Log("Waiting for Prometheus to become ready")

	test.Eventually(p.t, 2*time.Minute, func(t require.TestingT) {
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/-/ready", p.baseURL), nil)
		if err != nil {
			require.NoErrorf(t, err, "Failed to create readiness request")
			return
		}

		resp, err := p.client.Do(req)
		if err != nil {
			require.NoErrorf(t, err, "Failed to check Prometheus readiness")
			return
		}
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			p.t.Log("✓ Prometheus is ready")
			return
		}

		require.Failf(t, "Prometheus not ready",
			"Prometheus readiness check returned status %d", resp.StatusCode)
	}, test.Interval(2*time.Second))

	return nil
}

// WaitForMetricInRange waits for a metric value to be within a specified range
// This is useful for validating metrics like map utilization (0-100%) or rate limits
func (p *PrometheusClient) WaitForMetricInRange(ctx context.Context, metricName string, labels map[string]string, minValue, maxValue float64) error {
	p.t.Logf("Waiting for metric %s with labels %v to be in range [%f, %f]", metricName, labels, minValue, maxValue)

	test.Eventually(p.t, 2*time.Minute, func(t require.TestingT) {
		value, err := p.GetMetricValue(ctx, metricName, labels)
		require.NoError(t, err, "Failed to get metric value")

		if value < minValue || value > maxValue {
			require.Failf(t, "Metric out of range",
				"Metric %s value %f not in range [%f, %f]", metricName, value, minValue, maxValue)
		}

		p.t.Logf("✓ Metric %s value %f is within range", metricName, value)
	}, test.Interval(5*time.Second))

	return nil
}

// WaitForMetricIncrease waits for a metric value to increase over time
// This is useful for testing that counters are incrementing as expected
func (p *PrometheusClient) WaitForMetricIncrease(ctx context.Context, metricName string, labels map[string]string, duration time.Duration) error {
	p.t.Logf("Waiting for metric %s to increase over %s", metricName, duration)

	// Get initial value
	initialValue, err := p.GetMetricValue(ctx, metricName, labels)
	if err != nil {
		return fmt.Errorf("getting initial metric value: %w", err)
	}

	p.t.Logf("Initial value: %f", initialValue)

	// Wait for specified duration
	time.Sleep(duration)

	// Get final value
	finalValue, err := p.GetMetricValue(ctx, metricName, labels)
	if err != nil {
		return fmt.Errorf("getting final metric value: %w", err)
	}

	if finalValue <= initialValue {
		return fmt.Errorf("metric %s did not increase: initial=%f, final=%f", metricName, initialValue, finalValue)
	}

	p.t.Logf("✓ Metric %s increased from %f to %f over %s", metricName, initialValue, finalValue, duration)
	return nil
}

// QueryCardinality returns the number of unique time series for a metric
// This is critical for detecting metric cardinality explosions that can overwhelm Prometheus
func (p *PrometheusClient) QueryCardinality(ctx context.Context, metricName string) (int, error) {
	result, err := p.Query(ctx, fmt.Sprintf("count(%s)", metricName))
	if err != nil {
		return 0, fmt.Errorf("querying cardinality: %w", err)
	}

	if len(result.Data.Result) == 0 {
		return 0, nil
	}

	if len(result.Data.Result[0].Value) >= 2 {
		if valueStr, ok := result.Data.Result[0].Value[1].(string); ok {
			var count float64
			_, _ = fmt.Sscanf(valueStr, "%f", &count)
			return int(count), nil
		}
	}

	return 0, fmt.Errorf("invalid cardinality query result")
}

// GetMetricCardinality is a convenience wrapper for QueryCardinality that returns float64
// This is used by filter mode comparison tests to measure and compare cardinality across modes
func (p *PrometheusClient) GetMetricCardinality(ctx context.Context, metricName string) (float64, error) {
	cardinality, err := p.QueryCardinality(ctx, metricName)
	if err != nil {
		return 0, err
	}
	return float64(cardinality), nil
}

// AssertCardinalityBelowLimit verifies that metric cardinality is below a threshold
// This prevents metric explosions that can cause Prometheus performance issues
func (p *PrometheusClient) AssertCardinalityBelowLimit(ctx context.Context, metricName string, maxCardinality int) error {
	cardinality, err := p.QueryCardinality(ctx, metricName)
	if err != nil {
		return err
	}

	if cardinality > maxCardinality {
		return fmt.Errorf("metric %s cardinality %d exceeds limit %d", metricName, cardinality, maxCardinality)
	}

	p.t.Logf("✓ Metric %s cardinality %d is below limit %d", metricName, cardinality, maxCardinality)
	return nil
}

// GetMetricRate calculates the rate of change for a counter metric
// Uses Prometheus rate() function to calculate per-second rate over the given duration
func (p *PrometheusClient) GetMetricRate(ctx context.Context, metricName string, labels map[string]string, duration time.Duration) (float64, error) {
	// Build label selector
	labelSelectors := make([]string, 0, len(labels))
	for k, v := range labels {
		labelSelectors = append(labelSelectors, fmt.Sprintf("%s=%q", k, v))
	}

	query := fmt.Sprintf("rate(%s[%s])", metricName, duration.String())
	if len(labelSelectors) > 0 {
		query = fmt.Sprintf("rate(%s{%s}[%s])", metricName, strings.Join(labelSelectors, ","), duration.String())
	}

	result, err := p.Query(ctx, query)
	if err != nil {
		return 0, err
	}

	if len(result.Data.Result) == 0 {
		return 0, fmt.Errorf("metric rate not found")
	}

	// Get first result value
	if len(result.Data.Result[0].Value) >= 2 {
		if valueStr, ok := result.Data.Result[0].Value[1].(string); ok {
			var value float64
			_, _ = fmt.Sscanf(valueStr, "%f", &value)
			return value, nil
		}
	}

	return 0, fmt.Errorf("invalid metric rate format")
}

// AssertMetricRate verifies that a metric's rate is within expected bounds
func (p *PrometheusClient) AssertMetricRate(ctx context.Context, metricName string, labels map[string]string, duration time.Duration, minRate, maxRate float64) error {
	rate, err := p.GetMetricRate(ctx, metricName, labels, duration)
	if err != nil {
		return err
	}

	if rate < minRate || rate > maxRate {
		return fmt.Errorf("metric %s rate %f not in expected range [%f, %f]", metricName, rate, minRate, maxRate)
	}

	p.t.Logf("✓ Metric %s rate %f is within range [%f, %f]", metricName, rate, minRate, maxRate)
	return nil
}
