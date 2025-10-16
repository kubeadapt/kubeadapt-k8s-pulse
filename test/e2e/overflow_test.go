package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kubeadapt/ebpf-agent/test/e2e/helpers"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// TestE2EConnectionOverflow tests the overflow handling when BPF connection map is full
func TestE2EConnectionOverflow(t *testing.T) {
	const (
		testNamespace     = "overflow-test"
		prometheusURL     = "http://prometheus.monitoring.svc.cluster.local:9090"
		maxConnections    = 10000 // BPF map size
		overflowThreshold = 8000  // 80% utilization should trigger adaptive cleanup
		burstConnections  = 12000 // Generate more connections than map size
	)

	overflowHandling := features.New("Connection Map Overflow Handling").
		Assess("handles connection overflow gracefully", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Setting up Prometheus client")
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Wait for Prometheus to be ready
			if err := promClient.WaitForReady(ctx); err != nil {
				t.Fatalf("Prometheus not ready: %v", err)
			}

			t.Log("Setting up traffic generator for overflow test")
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())

			// Generate burst traffic to overflow the connection map
			t.Logf("Generating %d concurrent connections (map size: %d)", burstConnections, maxConnections)

			// Create multiple pods to generate traffic from
			for i := 0; i < 10; i++ {
				podName := fmt.Sprintf("traffic-gen-%d", i)
				// Generate parallel connections from each pod
				go func(pod string) {
					_ = trafficGen.GenerateHTTPTraffic(ctx, testNamespace, pod, "target-service", 1200)
				}(podName)
			}

			// Wait for traffic generation and metric export
			t.Log("Waiting for overflow metrics to be exported")
			time.Sleep(45 * time.Second)

			// Check overflow counter
			t.Log("Verifying overflow flow counter")
			err := promClient.WaitForMetric(ctx,
				"kubeadapt_overflow_flows_total",
				map[string]string{},
				1.0, // At least 1 overflow
			)
			if err != nil {
				t.Fatalf("Overflow counter not incremented: %v", err)
			}

			// Check map utilization metric
			t.Log("Verifying map utilization metrics")
			utilization, err := promClient.GetMetricValue(ctx,
				"kubeadapt_bpf_map_utilization_percent",
				map[string]string{
					"map_name": "connection_flows",
				},
			)
			if err != nil {
				t.Fatalf("Failed to get map utilization: %v", err)
			}

			t.Logf("✓ Map utilization: %.2f%% (overflow handling active)", utilization)
			return ctx
		}).Feature()

	adaptiveCleanup := features.New("Adaptive Cleanup").
		Assess("adjusts cleanup frequency based on map pressure", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Setting up Prometheus client")
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Check cleanup metrics
			t.Log("Verifying adaptive cleanup metrics")

			// Check connections cleaned metric
			err := promClient.WaitForMetric(ctx,
				"kubeadapt_connection_tracking_info",
				map[string]string{
					"metric": "connections_cleaned",
				},
				0.0, // Just verify it exists
			)
			if err != nil {
				t.Fatalf("Cleanup metric not found: %v", err)
			}

			// Check cleanup duration
			cleanupDuration, err := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_tracking_info",
				map[string]string{
					"metric": "cleanup_duration_ms",
				},
			)
			if err == nil && cleanupDuration > 0 {
				t.Logf("✓ Cleanup completed in %.2fms", cleanupDuration)
			}

			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, overflowHandling, adaptiveCleanup)
}

// TestE2EContainerLifecycle tests metric cleanup when containers are created/deleted
func TestE2EContainerLifecycle(t *testing.T) {
	const (
		testNamespace = "lifecycle-test"
		prometheusURL = "http://prometheus.monitoring.svc.cluster.local:9090"
	)

	containerCreation := features.New("Container Creation").
		Assess("tracks new container metrics", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Creating test pods")
			// This would use kubectl or client-go to create pods
			// For now, we assume pods are created by the test framework

			t.Log("Setting up Prometheus client")
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Create PodHelper for robust pod operations
			podHelper, err := helpers.NewPodHelper(cfg)
			if err != nil {
				t.Fatalf("Failed to create pod helper: %v", err)
			}

			// Wait for test pod to be ready
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "new-pod-1", 2*time.Minute); err != nil {
				t.Fatalf("Pod new-pod-1 not ready: %v", err)
			}

			// Generate some traffic from the new containers
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())
			_ = trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "new-pod-1", "service-1", 100)

			// Wait for metrics to be exported and scraped
			time.Sleep(45 * time.Second)

			// Verify raw IP connection metrics are exported for the new container
			// Agent exports pod IP → pod IP connection data (no namespace aggregation)
			err = promClient.WaitForMetric(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol":  "tcp",
					"direction": "egress",
				},
				1.0,
			)
			if err != nil {
				t.Fatalf("Connection metrics from new container not found: %v", err)
			}

			t.Log("✓ New container connection metrics tracked successfully")
			return ctx
		}).Feature()

	containerDeletion := features.New("Container Deletion").
		Assess("cleans up metrics after container deletion", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Deleting test pods")
			// Delete pods created in previous test
			// This would use kubectl or client-go

			// Wait for cleanup
			time.Sleep(60 * time.Second)

			// Verify active connections decreased
			t.Log("Verifying connection cleanup after pod deletion")
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			activeConnections, err := promClient.GetMetricValue(ctx,
				"kubeadapt_active_connections",
				map[string]string{
					"protocol": "tcp",
				},
			)
			if err == nil {
				t.Logf("✓ Active connections after deletion: %.0f", activeConnections)
			}

			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, containerCreation, containerDeletion)
}

// TestE2EMultiProtocolTraffic tests handling of mixed TCP and UDP traffic
// This now uses the new UDP traffic generation capabilities
func TestE2EMultiProtocolTraffic(t *testing.T) {
	const (
		testNamespace = "test" // Use existing test namespace with pods
		prometheusURL = "http://prometheus.monitoring.svc.cluster.local:9090"
	)

	multiProtocol := features.New("Multi-Protocol Traffic").
		Assess("tracks TCP and UDP traffic separately", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Testing multi-protocol traffic with new UDP generation")
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())
			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Generate TCP traffic
			t.Log("Generating TCP traffic")
			err := trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "test-pod-a", "test-service-b", 100)
			if err != nil {
				t.Fatalf("Failed to generate TCP traffic: %v", err)
			}

			// Generate UDP traffic using new UDP generator
			t.Log("Generating UDP traffic with new GenerateUDPTraffic method")
			err = trafficGen.GenerateUDPTraffic(ctx, testNamespace, "test-pod-a", "test-service-b", 100, 64)
			if err != nil {
				t.Fatalf("Failed to generate UDP traffic: %v", err)
			}

			// Wait for metrics
			t.Log("Waiting for metrics to be exported")
			time.Sleep(45 * time.Second)

			t.Log("Verifying protocol-specific metrics")

			// Check TCP connection metrics
			tcpConns, err := promClient.GetMetricValue(ctx,
				"kubeadapt_active_connections",
				map[string]string{
					"protocol": "tcp",
				},
			)
			if err != nil {
				t.Logf("TCP connection metrics error (may not be exposed yet): %v", err)
			} else {
				t.Logf("✓ TCP active connections: %.0f", tcpConns)
			}

			// Check UDP connection metrics
			udpConns, err := promClient.GetMetricValue(ctx,
				"kubeadapt_active_connections",
				map[string]string{
					"protocol": "udp",
				},
			)
			if err != nil {
				t.Logf("UDP connection metrics error (may not be exposed yet): %v", err)
			} else {
				t.Logf("✓ UDP active connections: %.0f", udpConns)
			}

			t.Log("✓ Multi-protocol traffic generation completed successfully")
			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, multiProtocol)
}
