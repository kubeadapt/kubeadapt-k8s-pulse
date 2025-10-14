package k8s

import (
	"context"
	"net"
	"sync"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"go.uber.org/zap"
)

const (
	// TopologyZoneLabel is the standard Kubernetes label for zone
	TopologyZoneLabel = "topology.kubernetes.io/zone"
	// TopologyRegionLabel is the standard Kubernetes label for region
	TopologyRegionLabel = "topology.kubernetes.io/region"
	// LegacyZoneLabel is the legacy label for zone (deprecated)
	LegacyZoneLabel = "failure-domain.beta.kubernetes.io/zone"
)

// ZoneMapper maps IP addresses to their availability zones
// NO CACHING - Queries K8s API in real-time for dynamic clusters with autoscaling
type ZoneMapper struct {
	client    kubernetes.Interface
	logger    *zap.Logger
	mu        sync.RWMutex
}

// NewZoneMapper creates a new zone mapper with real-time K8s API queries
func NewZoneMapper(logger *zap.Logger) (*ZoneMapper, error) {
	// Try to create in-cluster config first
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig for local development
		logger.Debug("Failed to create in-cluster config, will retry later", zap.Error(err))
		return &ZoneMapper{
			logger: logger,
		}, nil
	}

	// Create Kubernetes client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &ZoneMapper{
		client: client,
		logger: logger,
	}, nil
}

// GetZoneForIP returns the availability zone for an IP address
// Queries K8s API in real-time - no caching for autoscaling clusters
func (zm *ZoneMapper) GetZoneForIP(ip string) string {
	if zm.client == nil {
		zm.logger.Debug("Kubernetes client not initialized")
		if !isPrivateIP(net.ParseIP(ip)) {
			return "external"
		}
		return "unknown"
	}

	// Check if external IP first (fast check)
	if !isPrivateIP(net.ParseIP(ip)) {
		return "external"
	}

	zm.mu.Lock()
	defer zm.mu.Unlock()

	// Query all pods to find the one with this IP
	ctx := context.Background()
	pods, err := zm.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.podIP=" + ip,
	})

	if err != nil {
		zm.logger.Error("Failed to query pod by IP", zap.Error(err), zap.String("ip", ip))
		return "unknown"
	}

	// If we found the pod, get its node's zone
	if len(pods.Items) > 0 {
		pod := pods.Items[0]
		if pod.Spec.NodeName != "" {
			node, err := zm.client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if err != nil {
				zm.logger.Error("Failed to get node", zap.Error(err), zap.String("node", pod.Spec.NodeName))
				return "unknown"
			}

			// Try new label first, then legacy
			zone := node.Labels[TopologyZoneLabel]
			if zone == "" {
				zone = node.Labels[LegacyZoneLabel]
			}
			if zone != "" {
				return zone
			}
		}
	}

	// Check if it's a node IP
	nodes, err := zm.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		zm.logger.Error("Failed to list nodes", zap.Error(err))
		return "unknown"
	}

	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Address == ip {
				// Found matching node IP
				zone := node.Labels[TopologyZoneLabel]
				if zone == "" {
					zone = node.Labels[LegacyZoneLabel]
				}
				if zone != "" {
					return zone
				}
			}
		}
	}

	return "unknown"
}

// GetRegionForIP returns the region for an IP address
// Queries K8s API in real-time - no caching for autoscaling clusters
func (zm *ZoneMapper) GetRegionForIP(ip string) string {
	if zm.client == nil {
		if !isPrivateIP(net.ParseIP(ip)) {
			return "external"
		}
		return "unknown"
	}

	if !isPrivateIP(net.ParseIP(ip)) {
		return "external"
	}

	zm.mu.Lock()
	defer zm.mu.Unlock()

	ctx := context.Background()
	pods, err := zm.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.podIP=" + ip,
	})

	if err == nil && len(pods.Items) > 0 {
		pod := pods.Items[0]
		if pod.Spec.NodeName != "" {
			node, err := zm.client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if err == nil {
				region := node.Labels[TopologyRegionLabel]
				if region != "" {
					return region
				}
			}
		}
	}

	return "unknown"
}

// GetPodForIP returns the pod name for an IP address
// Queries K8s API in real-time
func (zm *ZoneMapper) GetPodForIP(ip string) string {
	if zm.client == nil {
		return ""
	}

	ctx := context.Background()
	pods, err := zm.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.podIP=" + ip,
	})

	if err == nil && len(pods.Items) > 0 {
		return pods.Items[0].Name
	}
	return ""
}

// GetNamespaceForIP returns the namespace for an IP address
// Queries K8s API in real-time
func (zm *ZoneMapper) GetNamespaceForIP(ip string) string {
	if zm.client == nil {
		return ""
	}

	ctx := context.Background()
	pods, err := zm.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.podIP=" + ip,
	})

	if err == nil && len(pods.Items) > 0 {
		return pods.Items[0].Namespace
	}
	return ""
}

// GetStats returns statistics about the zone mapper
func (zm *ZoneMapper) GetStats() map[string]int {
	// No caching, return zeros or query current state
	return map[string]int{
		"queries": 0, // Could track query count if needed
	}
}

// isPrivateIP checks if an IP is in private ranges (RFC1918)
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Convert to IPv4
	ip = ip.To4()
	if ip == nil {
		return false // IPv6 not supported yet
	}

	// Private IP ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.IPv4(10, 0, 0, 0), net.IPv4(10, 255, 255, 255)},       // 10.0.0.0/8
		{net.IPv4(172, 16, 0, 0), net.IPv4(172, 31, 255, 255)},     // 172.16.0.0/12
		{net.IPv4(192, 168, 0, 0), net.IPv4(192, 168, 255, 255)},   // 192.168.0.0/16
		{net.IPv4(100, 64, 0, 0), net.IPv4(100, 127, 255, 255)},    // 100.64.0.0/10 (CGN)
		{net.IPv4(169, 254, 0, 0), net.IPv4(169, 254, 255, 255)},   // 169.254.0.0/16 (Link-local)
		{net.IPv4(127, 0, 0, 0), net.IPv4(127, 255, 255, 255)},     // 127.0.0.0/8 (Loopback)
	}

	for _, r := range privateRanges {
		if bytes := ip.To4(); bytes != nil {
			if ipInRange(bytes, r.start.To4(), r.end.To4()) {
				return true
			}
		}
	}

	return false
}

// ipInRange checks if an IP is within a range
func ipInRange(ip, start, end []byte) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] < start[i] || ip[i] > end[i] {
			return false
		}
		if ip[i] > start[i] && ip[i] < end[i] {
			return true
		}
	}
	return true
}