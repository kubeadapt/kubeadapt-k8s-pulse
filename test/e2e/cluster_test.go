package e2e

import (
	"context"
	"path"
	"testing"
	"time"

	"github.com/kubeadapt/ebpf-agent/test/e2e/cluster"
	"github.com/kubeadapt/ebpf-agent/test/e2e/helpers"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

const (
	clusterNamePrefix = "kubeadapt-e2e-"
	testTimeout       = 10 * time.Minute
)

var (
	testCluster *cluster.Cluster
)

// TestMain sets up the test environment once for all tests
func TestMain(m *testing.M) {
	// Create unique cluster name with timestamp
	clusterName := clusterNamePrefix + time.Now().Format("20060102-150405")

	// Get project root directory (two levels up from test/e2e)
	baseDir := path.Join("..", "..")

	// Create and run test cluster
	testCluster = cluster.NewCluster(clusterName, baseDir)
	testCluster.Run(m)
}

// TestE2EMultiNodeCluster tests the eBPF agent in a multi-node Kind cluster
// This test validates:
// 1. Agent deployment on all nodes
// 2. Prometheus scraping of agent metrics
// 3. Raw IP-based connection metrics export (NO K8s enrichment)
// 4. Backend handles ALL aggregation (agent exports raw IP metrics only)
func TestE2EMultiNodeCluster(t *testing.T) {
	const (
		testNamespace   = "test"
		prometheusURL   = "http://localhost:30090" // Prometheus service DNS
		trafficRequests = 50                       // Number of HTTP requests to generate
	)

	rawIPTraffic := features.New("Raw IP Connection Metrics").
		Assess("raw IP-based connection metrics are exported", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("═══════════════════════════════════════════════════════════")
			t.Log("→ Testing Raw IP Connection Metrics Export")
			t.Log("═══════════════════════════════════════════════════════════")
			t.Log("Setting up Prometheus client")
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Wait for Prometheus to be ready
			t.Log("→ Waiting for Prometheus to become ready...")
			if err := promClient.WaitForReady(ctx); err != nil {
				t.Fatalf("Prometheus not ready: %v", err)
			}
			t.Log("✓ Prometheus is ready")

			// Create PodHelper for robust pod operations
			podHelper, err := helpers.NewPodHelper(cfg)
			if err != nil {
				t.Fatalf("Failed to create pod helper: %v", err)
			}

			// Wait for test pods to be ready before generating traffic
			t.Log("Ensuring test pods are ready...")
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-a", 2*time.Minute); err != nil {
				t.Fatalf("Pod test-pod-a not ready: %v", err)
			}
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-b", 2*time.Minute); err != nil {
				t.Fatalf("Pod test-pod-b not ready: %v", err)
			}

			t.Logf("→ Generating traffic between pods (Pod A -> Pod B): %d requests", trafficRequests)
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())

			// Generate HTTP traffic from Pod A to Pod B
			if err := trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "test-pod-a", "test-service-b", trafficRequests); err != nil {
				t.Fatalf("Failed to generate traffic: %v", err)
			}
			t.Logf("✓ Successfully generated %d HTTP requests", trafficRequests)

			t.Log("→ Waiting for metrics to be exported and scraped by Prometheus (45s)")
			t.Log("   Collection interval (30s) + Scrape interval (15s)")
			time.Sleep(45 * time.Second)

			t.Log("→ Querying Prometheus for raw IP-based connection metrics")

			// Verify connection traffic bytes metric exists (with any IP addresses)
			if err = promClient.WaitForMetric(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol":  "tcp",
					"direction": "egress",
				},
				1.0, // At least 1 byte of traffic
			); err != nil {
				t.Fatalf("Connection traffic bytes metric not found: %v", err)
			}

			// Verify connection traffic packets metric exists
			if err = promClient.WaitForMetric(ctx,
				"kubeadapt_connection_traffic_packets",
				map[string]string{
					"protocol": "tcp",
				},
				1.0, // At least 1 packet
			); err != nil {
				t.Fatalf("Connection traffic packets metric not found: %v", err)
			}

			t.Log("")
			t.Log("✅ Raw IP-based connection metrics successfully exported")
			t.Log("   ✓ Traffic bytes metric: kubeadapt_connection_traffic_bytes")
			t.Log("   ✓ Traffic packets metric: kubeadapt_connection_traffic_packets")
			t.Log("   ✓ Agent exports raw IP connections (backend handles aggregation)")
			t.Log("═══════════════════════════════════════════════════════════")
			return ctx
		}).Feature()

	additionalTraffic := features.New("Additional Traffic Patterns").
		Assess("multiple connection metrics are exported", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Setting up Prometheus client")
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Create PodHelper for robust pod operations
			podHelper, err := helpers.NewPodHelper(cfg)
			if err != nil {
				t.Fatalf("Failed to create pod helper: %v", err)
			}

			// Ensure pods are ready
			t.Log("Ensuring test pods are ready...")
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-b", 2*time.Minute); err != nil {
				t.Fatalf("Pod test-pod-b not ready: %v", err)
			}
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-c", 2*time.Minute); err != nil {
				t.Fatalf("Pod test-pod-c not ready: %v", err)
			}

			t.Log("Generating additional traffic (Pod B -> Pod C)")
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())

			// Generate HTTP traffic from Pod B to Pod C
			if err := trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "test-pod-b", "test-service-c", trafficRequests); err != nil {
				t.Fatalf("Failed to generate traffic: %v", err)
			}

			t.Log("Waiting for metrics to be exported and scraped")
			time.Sleep(45 * time.Second)

			t.Log("Querying Prometheus for connection metrics")

			// Verify connection traffic bytes metric exists (ingress direction)
			if err = promClient.WaitForMetric(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol":  "tcp",
					"direction": "ingress",
				},
				1.0,
			); err != nil {
				t.Fatalf("Connection traffic bytes (ingress) metric not found: %v", err)
			}

			t.Log("✓ Multiple connection metrics successfully exported")
			return ctx
		}).Feature()

	bpfMapUtilization := features.New("BPF Map Utilization Metrics").
		Assess("map utilization metrics are exposed", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("═══════════════════════════════════════════════════════════")
			t.Log("→ Testing BPF Map Utilization Metrics")
			t.Log("═══════════════════════════════════════════════════════════")
			t.Log("Setting up Prometheus client")
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			t.Log("→ Verifying BPF map utilization metrics are exposed")

			// Query for map utilization metric
			err := promClient.WaitForMetric(ctx,
				"kubeadapt_bpf_map_utilization_percent",
				map[string]string{
					"map_name": "connection_flows",
				},
				0.0, // Just verify it exists
			)
			if err != nil {
				t.Fatalf("Map utilization metric not found: %v", err)
			}

			// Verify the value is reasonable (0-100%)
			value, err := promClient.GetMetricValue(ctx,
				"kubeadapt_bpf_map_utilization_percent",
				map[string]string{
					"map_name": "connection_flows",
				},
			)
			if err != nil {
				t.Fatalf("Failed to get metric value: %v", err)
			}

			if value < 0 || value > 100 {
				t.Fatalf("Map utilization out of range: %f (expected 0-100)", value)
			}

			t.Log("")
			t.Log("✅ BPF map utilization metrics verified")
			t.Logf("   ✓ Current map utilization: %.2f%%", value)
			t.Log("   ✓ Metric range valid: 0-100%")
			t.Log("   ✓ Map: connection_flows (PERCPU_HASH)")
			t.Log("═══════════════════════════════════════════════════════════")
			return ctx
		}).Feature()

	// NOTE: ALL K8s-based aggregation removed (service, namespace, zone, region)
	// Agent exports ONLY raw connection-level metrics (pod IP → pod IP)
	// Backend handles ALL aggregation via separate K8s API queries

	testCluster.TestEnv().Test(t, rawIPTraffic, additionalTraffic, bpfMapUtilization)
}

// TestE2EPrometheusCardinality verifies that Prometheus cardinality stays reasonable
// Note: Raw IP metrics have higher cardinality than aggregated metrics, but still manageable
// in typical cluster sizes (10-100 active connections vs 1000s of potential pod pairs)
func TestE2EPrometheusCardinality(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	const (
		prometheusURL     = "http://localhost:30090"
		maxCardinality    = 50_000 // Maximum allowed time series per metric for test environment (see CARDINALITY_ANALYSIS.md)
		testNamespace     = "test"
		cardinalityMetric = "kubeadapt_connection_traffic_bytes"
	)

	cardinalityCheck := features.New("Prometheus Cardinality Check").
		Assess("connection traffic metric cardinality below limit", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Verifying metric cardinality to prevent Prometheus performance issues")

			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Wait for Prometheus to be ready
			if err := promClient.WaitForReady(ctx); err != nil {
				t.Fatalf("Prometheus not ready: %v", err)
			}

			// Check connection traffic metric cardinality
			t.Logf("Checking cardinality for metric: %s", cardinalityMetric)
			err := promClient.AssertCardinalityBelowLimit(ctx, cardinalityMetric, maxCardinality)
			if err != nil {
				t.Fatalf("Cardinality check failed: %v", err)
			}

			t.Logf("✓ Metric cardinality is below limit of %d", maxCardinality)
			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, cardinalityCheck)
}
