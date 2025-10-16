package helpers

import (
	"bytes"
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// TestingT is a minimal interface for testing.T to enable better testability
type TestingT interface {
	Logf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	FailNow()
	Helper()
}

// PodHelper provides utilities for interacting with pods in E2E tests
// Follows NetObserv's pattern from e2e/cluster/tester/pods.go
type PodHelper struct {
	restConfig *rest.Config
	clientset  *kubernetes.Clientset
}

// NewPodHelper creates a new PodHelper from an envconf.Config
func NewPodHelper(cfg *envconf.Config) (*PodHelper, error) {
	clientset, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes clientset: %w", err)
	}

	return &PodHelper{
		restConfig: cfg.Client().RESTConfig(),
		clientset:  clientset,
	}, nil
}

// NewPodHelperFromConfig creates a new PodHelper from a rest.Config
func NewPodHelperFromConfig(config *rest.Config) (*PodHelper, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes clientset: %w", err)
	}

	return &PodHelper{
		restConfig: config,
		clientset:  clientset,
	}, nil
}

// Execute runs a command in a pod and returns stdout, stderr, and error
// This is similar to NetObserv's Pods.Execute method
func (p *PodHelper) Execute(ctx context.Context, namespace, name string, command ...string) (stdout, stderr string, err error) {
	pod, err := p.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("getting pod %s/%s: %w", namespace, name, err)
	}

	// If pod has multiple containers, use the first one
	// In production, we might want to allow specifying the container
	containerName := ""
	if len(pod.Spec.Containers) > 0 {
		containerName = pod.Spec.Containers[0].Name
	}

	request := p.clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   command,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(p.restConfig, "POST", request.URL())
	if err != nil {
		return "", "", fmt.Errorf("creating executor: %w", err)
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: stdoutBuf,
		Stderr: stderrBuf,
	})

	return stdoutBuf.String(), stderrBuf.String(), err
}

// WaitForReady waits for a pod to be in Running state with all containers ready
// Uses test.Eventually pattern for robust waiting with clear error messages
func (p *PodHelper) WaitForReady(ctx context.Context, t TestingT, namespace, name string, timeout time.Duration) error {
	t.Helper()
	t.Logf("Waiting for pod %s/%s to be ready (timeout: %s)", namespace, name, timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastError error

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled while waiting for pod %s/%s: %w", namespace, name, ctx.Err())
		case <-time.After(time.Until(deadline)):
			if lastError != nil {
				return fmt.Errorf("timeout waiting for pod %s/%s to be ready: %w", namespace, name, lastError)
			}
			return fmt.Errorf("timeout waiting for pod %s/%s to be ready", namespace, name)
		case <-ticker.C:
			pod, err := p.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				lastError = fmt.Errorf("getting pod: %w", err)
				t.Logf("Error getting pod %s/%s (will retry): %v", namespace, name, err)
				continue
			}

			// Check pod phase
			if pod.Status.Phase != corev1.PodRunning {
				lastError = fmt.Errorf("pod phase is %s (expected Running)", pod.Status.Phase)
				t.Logf("Pod %s/%s phase: %s (waiting for Running)", namespace, name, pod.Status.Phase)

				// Log additional details if pod is pending or failed
				if pod.Status.Phase == corev1.PodPending {
					for _, cond := range pod.Status.Conditions {
						if cond.Status == corev1.ConditionFalse {
							t.Logf("  Condition %s: %s - %s", cond.Type, cond.Reason, cond.Message)
						}
					}
				}
				if pod.Status.Phase == corev1.PodFailed {
					return fmt.Errorf("pod %s/%s is in Failed state: %s", namespace, name, pod.Status.Message)
				}
				continue
			}

			// Check container statuses
			allReady := true
			for _, cs := range pod.Status.ContainerStatuses {
				if !cs.Ready {
					allReady = false
					lastError = fmt.Errorf("container %s not ready", cs.Name)

					// Log container state details
					if cs.State.Waiting != nil {
						t.Logf("  Container %s waiting: %s - %s", cs.Name, cs.State.Waiting.Reason, cs.State.Waiting.Message)
					}
					if cs.State.Terminated != nil {
						t.Logf("  Container %s terminated: %s (exit code %d)", cs.Name, cs.State.Terminated.Reason, cs.State.Terminated.ExitCode)
					}
					break
				}
			}

			if !allReady {
				continue
			}

			// Check readiness conditions
			ready := false
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}

			if !ready {
				lastError = fmt.Errorf("pod Ready condition not true")
				t.Logf("Pod %s/%s containers running but Ready condition not true", namespace, name)
				continue
			}

			// Pod is fully ready
			t.Logf("✓ Pod %s/%s is ready (IP: %s)", namespace, name, pod.Status.PodIP)
			return nil
		}
	}
}

// DaemonSetReady checks if a DaemonSet has all desired pods ready
// Similar to NetObserv's Pods.DSReady method
func (p *PodHelper) DaemonSetReady(ctx context.Context, namespace, name string) error {
	ds, err := p.clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting daemonset %s/%s: %w", namespace, name, err)
	}

	if ds.Status.NumberReady == 0 {
		return fmt.Errorf("daemonset %s/%s has 0 ready pods (desired: %d)",
			namespace, name, ds.Status.DesiredNumberScheduled)
	}

	if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
		return fmt.Errorf("daemonset %s/%s not ready: %d/%d pods ready",
			namespace, name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
	}

	// Check for updated pods
	if ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
		return fmt.Errorf("daemonset %s/%s not fully updated: %d/%d pods updated",
			namespace, name, ds.Status.UpdatedNumberScheduled, ds.Status.DesiredNumberScheduled)
	}

	// Check for available pods
	if ds.Status.NumberAvailable != ds.Status.DesiredNumberScheduled {
		return fmt.Errorf("daemonset %s/%s not fully available: %d/%d pods available",
			namespace, name, ds.Status.NumberAvailable, ds.Status.DesiredNumberScheduled)
	}

	return nil
}

// GetIP returns the IP address of a pod
func (p *PodHelper) GetIP(ctx context.Context, namespace, name string) (string, error) {
	pod, err := p.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting pod %s/%s: %w", namespace, name, err)
	}

	if pod.Status.PodIP == "" {
		return "", fmt.Errorf("pod %s/%s has no IP assigned", namespace, name)
	}

	return pod.Status.PodIP, nil
}

// GetNode returns the node name where the pod is scheduled
func (p *PodHelper) GetNode(ctx context.Context, namespace, name string) (string, error) {
	pod, err := p.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting pod %s/%s: %w", namespace, name, err)
	}

	if pod.Spec.NodeName == "" {
		return "", fmt.Errorf("pod %s/%s has no node assigned", namespace, name)
	}

	return pod.Spec.NodeName, nil
}

// GetZone returns the availability zone of the node where the pod is scheduled
// This queries the node's topology.kubernetes.io/zone label
func (p *PodHelper) GetZone(ctx context.Context, namespace, name string) (string, error) {
	nodeName, err := p.GetNode(ctx, namespace, name)
	if err != nil {
		return "", err
	}

	node, err := p.clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting node %s: %w", nodeName, err)
	}

	// Try new label first, then legacy
	zone := node.Labels["topology.kubernetes.io/zone"]
	if zone == "" {
		zone = node.Labels["failure-domain.beta.kubernetes.io/zone"]
	}
	if zone == "" {
		return "", fmt.Errorf("node %s has no zone label", nodeName)
	}

	return zone, nil
}

// WaitForDaemonSetReady is a convenience wrapper for DaemonSetReady with retry logic
func (p *PodHelper) WaitForDaemonSetReady(ctx context.Context, t TestingT, namespace, name string, timeout time.Duration) error {
	t.Helper()
	t.Logf("Waiting for daemonset %s/%s to be ready (timeout: %s)", namespace, name, timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastError error

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		case <-time.After(time.Until(deadline)):
			if lastError != nil {
				return fmt.Errorf("timeout: %w", lastError)
			}
			return fmt.Errorf("timeout waiting for daemonset %s/%s", namespace, name)
		case <-ticker.C:
			err := p.DaemonSetReady(ctx, namespace, name)
			if err == nil {
				t.Logf("✓ DaemonSet %s/%s is ready", namespace, name)
				return nil
			}
			lastError = err
			t.Logf("DaemonSet %s/%s not ready: %v (will retry)", namespace, name, err)
		}
	}
}

// WaitForDeploymentReady waits for a Deployment to be fully ready
func (p *PodHelper) WaitForDeploymentReady(ctx context.Context, t TestingT, namespace, name string, timeout time.Duration) error {
	t.Helper()
	t.Logf("Waiting for deployment %s/%s to be ready (timeout: %s)", namespace, name, timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastError error

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		case <-time.After(time.Until(deadline)):
			if lastError != nil {
				return fmt.Errorf("timeout: %w", lastError)
			}
			return fmt.Errorf("timeout waiting for deployment %s/%s", namespace, name)
		case <-ticker.C:
			deploy, err := p.clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				lastError = fmt.Errorf("getting deployment: %w", err)
				t.Logf("Error getting deployment %s/%s: %v (will retry)", namespace, name, err)
				continue
			}

			if deploy.Status.ReadyReplicas != *deploy.Spec.Replicas {
				lastError = fmt.Errorf("%d/%d replicas ready", deploy.Status.ReadyReplicas, *deploy.Spec.Replicas)
				t.Logf("Deployment %s/%s: %d/%d replicas ready (waiting...)",
					namespace, name, deploy.Status.ReadyReplicas, *deploy.Spec.Replicas)
				continue
			}

			if deploy.Status.UpdatedReplicas != *deploy.Spec.Replicas {
				lastError = fmt.Errorf("%d/%d replicas updated", deploy.Status.UpdatedReplicas, *deploy.Spec.Replicas)
				t.Logf("Deployment %s/%s: %d/%d replicas updated (waiting...)",
					namespace, name, deploy.Status.UpdatedReplicas, *deploy.Spec.Replicas)
				continue
			}

			t.Logf("✓ Deployment %s/%s is ready", namespace, name)
			return nil
		}
	}
}

// ListPods returns all pods in a namespace matching the given label selector
func (p *PodHelper) ListPods(ctx context.Context, namespace string, labelSelector string) ([]corev1.Pod, error) {
	pods, err := p.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pods in namespace %s: %w", namespace, err)
	}

	return pods.Items, nil
}

// WaitForPodCondition waits for a specific pod condition to be true
func (p *PodHelper) WaitForPodCondition(ctx context.Context, t TestingT, namespace, name string, conditionType corev1.PodConditionType, timeout time.Duration) error {
	t.Helper()
	t.Logf("Waiting for pod %s/%s condition %s (timeout: %s)", namespace, name, conditionType, timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		case <-time.After(time.Until(deadline)):
			return fmt.Errorf("timeout waiting for condition %s on pod %s/%s", conditionType, namespace, name)
		case <-ticker.C:
			pod, err := p.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				t.Logf("Error getting pod: %v (will retry)", err)
				continue
			}

			for _, cond := range pod.Status.Conditions {
				if cond.Type == conditionType && cond.Status == corev1.ConditionTrue {
					t.Logf("✓ Pod %s/%s condition %s is true", namespace, name, conditionType)
					return nil
				}
			}

			t.Logf("Pod %s/%s condition %s not yet true (waiting...)", namespace, name, conditionType)
		}
	}
}

// WaitForPodsReadyByLabel waits for all pods matching a label selector to be ready
func (p *PodHelper) WaitForPodsReadyByLabel(ctx context.Context, t TestingT, namespace, labelSelector string, timeout time.Duration) error {
	t.Helper()
	t.Logf("Waiting for pods with label %s in namespace %s to be ready (timeout: %s)", labelSelector, namespace, timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		case <-time.After(time.Until(deadline)):
			return fmt.Errorf("timeout waiting for pods with label %s", labelSelector)
		case <-ticker.C:
			pods, err := p.ListPods(ctx, namespace, labelSelector)
			if err != nil {
				t.Logf("Error listing pods: %v (will retry)", err)
				continue
			}

			if len(pods) == 0 {
				t.Logf("No pods found with label %s (waiting...)", labelSelector)
				continue
			}

			allReady := true
			for _, pod := range pods {
				if pod.Status.Phase != corev1.PodRunning {
					t.Logf("Pod %s not running: %s", pod.Name, pod.Status.Phase)
					allReady = false
					break
				}

				ready := false
				for _, cond := range pod.Status.Conditions {
					if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
						ready = true
						break
					}
				}
				if !ready {
					t.Logf("Pod %s not ready", pod.Name)
					allReady = false
					break
				}
			}

			if allReady {
				t.Logf("✓ All %d pods with label %s are ready", len(pods), labelSelector)
				return nil
			}
		}
	}
}

// WaitForDaemonSetReadyWithResources is a helper that uses the e2e-framework resources client
// This is useful for integration with existing cluster setup code
func WaitForDaemonSetReadyWithResources(namespace, name string) func(*envconf.Config) error {
	return func(cfg *envconf.Config) error {
		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return fmt.Errorf("creating resources client: %w", err)
		}

		var ds appsv1.DaemonSet
		if err := r.Get(context.Background(), name, namespace, &ds); err != nil {
			return fmt.Errorf("getting daemonset %s/%s: %w", namespace, name, err)
		}

		if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not ready: %d/%d pods ready",
				namespace, name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
		}

		if ds.Status.NumberAvailable != ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not fully available: %d/%d pods available",
				namespace, name, ds.Status.NumberAvailable, ds.Status.DesiredNumberScheduled)
		}

		return nil
	}
}
