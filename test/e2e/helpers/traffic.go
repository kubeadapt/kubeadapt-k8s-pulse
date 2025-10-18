package helpers

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// TrafficGenerator helps generate network traffic between pods for E2E tests
type TrafficGenerator struct {
	t         *testing.T
	clientset *kubernetes.Clientset
	config    *rest.Config
}

// NewTrafficGenerator creates a new traffic generator
func NewTrafficGenerator(t *testing.T, config *rest.Config) *TrafficGenerator {
	// Create kubernetes clientset from config
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("Failed to create kubernetes clientset: %v", err)
	}

	return &TrafficGenerator{
		t:         t,
		clientset: clientset,
		config:    config,
	}
}

// GenerateHTTPTraffic generates HTTP traffic from source pod to destination service
// This executes curl inside the source pod to make requests to the destination
func (tg *TrafficGenerator) GenerateHTTPTraffic(ctx context.Context, namespace, sourcePod, destService string, requests int) error {
	tg.t.Logf("Generating %d HTTP requests from %s/%s to %s", requests, namespace, sourcePod, destService)

	// Wait for pod to be ready
	if err := tg.waitForPodReady(ctx, namespace, sourcePod); err != nil {
		return fmt.Errorf("waiting for pod ready: %w", err)
	}

	// Build curl command to generate traffic
	// -s: silent, -o /dev/null: discard output, --max-time: timeout
	curlCmd := fmt.Sprintf(
		"for i in $(seq 1 %d); do curl -s -o /dev/null --max-time 2 http://%s.%s.svc.cluster.local || true; sleep 0.1; done",
		requests, destService, namespace,
	)

	// Determine container name based on pod name
	// Traffic generator pods use "generator", regular test pods use "nginx"
	containerName := tg.getContainerName(sourcePod)

	// Execute curl in the pod
	stdout, stderr, err := tg.execInPod(ctx, namespace, sourcePod, containerName, []string{"/bin/sh", "-c", curlCmd})
	if err != nil {
		tg.t.Logf("Traffic generation stderr: %s", stderr)
		return fmt.Errorf("executing curl in pod: %w", err)
	}

	tg.t.Logf("Traffic generation completed. Stdout: %s", stdout)
	return nil
}

// GenerateBurstHTTPTraffic generates HTTP traffic in BURST MODE (no delay between requests)
// This is used for overflow testing where we need to fill the BPF map faster than
// the collector can clear it (25-second collection interval).
// Target: Generate all traffic within < 20 seconds to complete within one collection cycle.
func (tg *TrafficGenerator) GenerateBurstHTTPTraffic(ctx context.Context, namespace, sourcePod, destService string, requests int) error {
	tg.t.Logf("Generating %d HTTP requests in BURST MODE from %s/%s to %s", requests, namespace, sourcePod, destService)

	// Wait for pod to be ready
	if err := tg.waitForPodReady(ctx, namespace, sourcePod); err != nil {
		return fmt.Errorf("waiting for pod ready: %w", err)
	}

	// Build curl command for BURST traffic generation
	// Key differences from normal traffic:
	// - NO SLEEP between requests (removed 'sleep 0.1')
	// - Shorter timeout (1 second vs 2 seconds)
	// - High concurrency via xargs parallel execution
	//
	// Parallelism tuning results (nginx alpine + curl architecture):
	// - -P 10:   ~30 req/sec
	// - -P 200:  424-580 req/sec ← OPTIMAL (best throughput)
	// - -P 2000: 424-476 req/sec (worse due to context switching overhead)
	//
	// Conclusion: -P 200 is optimal. Architecture has hard limit ~600 req/sec.
	curlCmd := fmt.Sprintf(
		"seq 1 %d | xargs -I {} -P 200 curl -s -o /dev/null --max-time 1 http://%s.%s.svc.cluster.local 2>/dev/null || true",
		requests, destService, namespace,
	)

	// Determine container name based on pod name
	containerName := tg.getContainerName(sourcePod)

	// Execute curl in the pod
	start := time.Now()
	stdout, stderr, err := tg.execInPod(ctx, namespace, sourcePod, containerName, []string{"/bin/sh", "-c", curlCmd})
	duration := time.Since(start)

	if err != nil {
		tg.t.Logf("Burst traffic generation stderr: %s", stderr)
		return fmt.Errorf("executing burst curl in pod: %w", err)
	}

	tg.t.Logf("✓ Burst traffic generation completed in %v (~%.0f req/sec)", duration, float64(requests)/duration.Seconds())
	tg.t.Logf("  Stdout: %s", stdout)
	return nil
}

// GenerateContinuousTraffic generates continuous traffic in the background
// Returns a cancel function to stop the traffic generation
func (tg *TrafficGenerator) GenerateContinuousTraffic(ctx context.Context, namespace, sourcePod, destService string) (context.CancelFunc, error) {
	tg.t.Logf("Starting continuous traffic from %s/%s to %s", namespace, sourcePod, destService)

	// Wait for pod to be ready
	if err := tg.waitForPodReady(ctx, namespace, sourcePod); err != nil {
		return nil, fmt.Errorf("waiting for pod ready: %w", err)
	}

	// Determine container name based on pod name
	containerName := tg.getContainerName(sourcePod)

	// Create cancellable context
	trafficCtx, cancel := context.WithCancel(ctx)

	// Start traffic in background
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-trafficCtx.Done():
				tg.t.Logf("Stopping continuous traffic from %s to %s", sourcePod, destService)
				return
			case <-ticker.C:
				curlCmd := fmt.Sprintf("curl -s -o /dev/null --max-time 1 http://%s.%s.svc.cluster.local || true",
					destService, namespace)

				_, _, _ = tg.execInPod(trafficCtx, namespace, sourcePod, containerName, []string{"/bin/sh", "-c", curlCmd})
			}
		}
	}()

	return cancel, nil
}

// execInPod executes a command in a pod container
func (tg *TrafficGenerator) execInPod(ctx context.Context, namespace, pod, container string, command []string) (string, string, error) {
	req := tg.clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(tg.config, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("creating executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	return stdout.String(), stderr.String(), err
}

// GenerateUDPTraffic generates UDP traffic from source pod to destination service
// Uses netcat (nc) to send UDP packets, following NetObserv's approach
func (tg *TrafficGenerator) GenerateUDPTraffic(ctx context.Context, namespace, sourcePod, destService string, packets int, packetSize int) error {
	tg.t.Logf("Generating %d UDP packets (%d bytes each) from %s/%s to %s", packets, packetSize, namespace, sourcePod, destService)

	// Wait for pod to be ready
	if err := tg.waitForPodReady(ctx, namespace, sourcePod); err != nil {
		return fmt.Errorf("waiting for pod ready: %w", err)
	}

	// Build netcat command for UDP traffic
	// nc -u = UDP mode, -w1 = 1 second timeout
	// We use port 53 (DNS) as it's commonly open and won't be blocked
	payload := generatePayload(packetSize)
	ncCmd := fmt.Sprintf(
		"for i in $(seq 1 %d); do echo '%s' | nc -u -w1 %s.%s.svc.cluster.local 53 || true; sleep 0.1; done",
		packets,
		payload,
		destService,
		namespace,
	)

	// Determine container name based on pod name
	containerName := tg.getContainerName(sourcePod)

	// Execute netcat in the pod
	stdout, stderr, err := tg.execInPod(ctx, namespace, sourcePod, containerName, []string{"/bin/sh", "-c", ncCmd})
	if err != nil {
		tg.t.Logf("UDP traffic generation stderr: %s", stderr)
		return fmt.Errorf("executing netcat in pod: %w", err)
	}

	tg.t.Logf("UDP traffic generation completed. Stdout: %s", stdout)
	return nil
}

// GenerateMixedProtocolTraffic generates both TCP and UDP traffic
// This is useful for testing multi-protocol tracking capabilities
func (tg *TrafficGenerator) GenerateMixedProtocolTraffic(ctx context.Context, namespace, sourcePod, destService string, httpRequests, udpPackets int) error {
	tg.t.Logf("Generating mixed protocol traffic: %d HTTP requests + %d UDP packets", httpRequests, udpPackets)

	// Generate HTTP (TCP) traffic
	if err := tg.GenerateHTTPTraffic(ctx, namespace, sourcePod, destService, httpRequests); err != nil {
		return fmt.Errorf("generating HTTP traffic: %w", err)
	}

	// Generate UDP traffic
	if err := tg.GenerateUDPTraffic(ctx, namespace, sourcePod, destService, udpPackets, 64); err != nil {
		return fmt.Errorf("generating UDP traffic: %w", err)
	}

	tg.t.Log("✓ Mixed protocol traffic generation completed")
	return nil
}

// generatePayload creates a payload string of the specified size
func generatePayload(size int) string {
	if size <= 0 {
		return ""
	}
	// Use 'X' characters for payload, escaped for shell
	payload := ""
	for i := 0; i < size && i < 1024; i++ { // Limit to 1KB for safety
		payload += "X"
	}
	return payload
}

// getContainerName returns the appropriate container name for a given pod
// Traffic generator pods (traffic-gen-*) use "generator" container
// Regular test pods use "nginx" container
func (tg *TrafficGenerator) getContainerName(podName string) string {
	if len(podName) >= 11 && podName[:11] == "traffic-gen" {
		return "generator"
	}
	return "nginx"
}

// waitForPodReady waits for a pod to be in Running state and all containers ready using test.Eventually
func (tg *TrafficGenerator) waitForPodReady(ctx context.Context, namespace, podName string) error {
	tg.t.Logf("Waiting for pod %s/%s to be ready", namespace, podName)

	test.Eventually(tg.t, 2*time.Minute, func(t require.TestingT) {
		pod, err := tg.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			require.NoErrorf(t, err, "Failed to get pod %s/%s", namespace, podName)
			return
		}

		if pod.Status.Phase != corev1.PodRunning {
			require.Failf(t, "Pod not running",
				"Pod %s/%s phase is %s (expected Running)", namespace, podName, pod.Status.Phase)
			return
		}

		// Check if all containers are ready
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				require.Failf(t, "Container not ready",
					"Container %s in pod %s/%s not ready", cs.Name, namespace, podName)
				return
			}
		}

		// Check readiness condition
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				tg.t.Logf("✓ Pod %s/%s is ready", namespace, podName)
				return
			}
		}

		require.Failf(t, "Pod Ready condition not true",
			"Pod %s/%s Ready condition not met", namespace, podName)
	}, test.Interval(2*time.Second))

	return nil
}
