package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	// Container runtime type constants
	runtimeTypeDocker = "docker"
)

// ProcDiscoverer discovers containers by scanning /proc
type ProcDiscoverer struct {
	procPath string
	logger   *zap.Logger
}

// NewProcDiscoverer creates a new /proc-based container discoverer
func NewProcDiscoverer(procPath string, logger *zap.Logger) (*ProcDiscoverer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	if procPath == "" {
		procPath = "/host/proc"
		if _, err := os.Stat(procPath); os.IsNotExist(err) {
			procPath = "/proc"
		}
	}

	return &ProcDiscoverer{
		procPath: procPath,
		logger:   logger,
	}, nil
}

// Start begins the discovery process
func (d *ProcDiscoverer) Start(ctx context.Context, cache *Cache) error {
	d.logger.Info("Starting proc-based container discovery", zap.String("procPath", d.procPath))

	// Initial scan
	if err := d.scanContainers(cache); err != nil {
		d.logger.Error("Initial scan failed", zap.Error(err))
	}

	// Periodic rescan
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("Stopping proc discovery")
			return nil
		case <-ticker.C:
			if err := d.scanContainers(cache); err != nil {
				d.logger.Error("Periodic scan failed", zap.Error(err))
			}
		}
	}
}

// scanContainers scans /proc for container processes
func (d *ProcDiscoverer) scanContainers(cache *Cache) error {
	d.logger.Debug("Scanning /proc for containers")

	entries, err := os.ReadDir(d.procPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", d.procPath, err)
	}

	foundContainers := make(map[string]*Info)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if this is a PID directory
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read cgroup file to determine if this is a container process
		info := d.getContainerInfo(pid)
		if info != nil && info.ContainerID != "" {
			foundContainers[info.ContainerID] = info
		}
	}

	// Update cache
	for _, info := range foundContainers {
		cache.Add(info)
	}

	stats := cache.Stats()
	d.logger.Info("Proc scan completed",
		zap.Int("containers_found", len(foundContainers)),
		zap.Int("total_cached", stats.TotalContainers),
	)

	return nil
}

// getContainerInfo extracts container information from a process
func (d *ProcDiscoverer) getContainerInfo(pid int) *Info {
	cgroupPath := filepath.Join(d.procPath, strconv.Itoa(pid), "cgroup")

	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil
	}

	// Parse cgroup file
	var cgroupID uint64
	var containerID string
	var containerName string

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Example line: "0::/kubepods/pod-xxx/container-xxx"
		// or: "12:memory:/docker/abc123..."
		// or: "0::/system.slice/containerd.service/xxx"

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		path := parts[2]

		// Check for Docker container
		if strings.Contains(path, "/docker/") {
			idx := strings.Index(path, "/docker/")
			if idx >= 0 {
				containerPart := path[idx+8:] // Skip "/docker/"
				if slashIdx := strings.Index(containerPart, "/"); slashIdx > 0 {
					containerID = containerPart[:slashIdx]
				} else {
					containerID = containerPart
				}
				if len(containerID) > 12 {
					containerID = containerID[:12]
				}
			}
		}

		// Check for containerd container
		if strings.Contains(path, "containerd") {
			// Extract container ID from containerd path
			parts := strings.Split(path, "/")
			for _, part := range parts {
				if strings.HasPrefix(part, "cri-containerd-") {
					containerID = strings.TrimPrefix(part, "cri-containerd-")
					containerID = strings.TrimSuffix(containerID, ".scope")
					if len(containerID) > 12 {
						containerID = containerID[:12]
					}
					break
				}
			}
		}

		// Extract cgroup ID (using cgroup v2 format)
		if strings.HasPrefix(line, "0::") {
			cgroupID = d.getCgroupIDFromPath(path)
		}
	}

	if containerID == "" {
		return nil
	}

	// Get additional info from process
	cmdlinePath := filepath.Join(d.procPath, strconv.Itoa(pid), "cmdline")
	cmdlineData, _ := os.ReadFile(cmdlinePath)
	cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")

	// Try to extract container name from cmdline or environ
	environPath := filepath.Join(d.procPath, strconv.Itoa(pid), "environ")
	environData, _ := os.ReadFile(environPath)
	environ := strings.Split(string(environData), "\x00")

	for _, env := range environ {
		if strings.HasPrefix(env, "CONTAINER_NAME=") {
			containerName = strings.TrimPrefix(env, "CONTAINER_NAME=")
			// Note: we could also extract K8S_POD_NAME if needed in the future
		}
	}

	// If no container name found, try to extract from cmdline
	if containerName == "" {
		// Simple heuristic: use the first meaningful command
		cmdParts := strings.Fields(cmdline)
		if len(cmdParts) > 0 {
			containerName = filepath.Base(cmdParts[0])
		}
	}

	// Get container start time
	statPath := filepath.Join(d.procPath, strconv.Itoa(pid), "stat")
	startTime := d.getProcessStartTime(statPath)

	return &Info{
		ContainerID:   containerID,
		ContainerName: containerName,
		CgroupID:      cgroupID,
		PID:           pid,
		StartTime:     startTime,
		RuntimeType:   d.detectRuntimeType(containerID, cmdline),
	}
}

// getCgroupIDFromPath extracts cgroup ID from path
func (d *ProcDiscoverer) getCgroupIDFromPath(path string) uint64 {
	// Try to get the actual inode of the cgroup directory
	fullPath := filepath.Join("/sys/fs/cgroup", path)

	info, err := os.Stat(fullPath)
	if err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			return stat.Ino
		}
	}

	// Fallback: generate ID from path
	var hash uint64
	for _, c := range path {
		hash = hash*31 + uint64(c)
	}
	return hash
}

// getProcessStartTime gets the process start time
func (d *ProcDiscoverer) getProcessStartTime(statPath string) time.Time {
	data, err := os.ReadFile(statPath)
	if err != nil {
		return time.Now()
	}

	// Parse /proc/[pid]/stat
	// Field 22 is starttime (jiffies since boot)
	fields := strings.Fields(string(data))
	if len(fields) > 21 {
		if starttime, err := strconv.ParseInt(fields[21], 10, 64); err == nil {
			// Convert jiffies to time
			// Note: This is simplified - in production you'd need to get the actual HZ value
			const HZ = 100
			bootTime := d.getBootTime()
			return bootTime.Add(time.Duration(starttime) * time.Second / HZ)
		}
	}

	return time.Now()
}

// getBootTime gets the system boot time
func (d *ProcDiscoverer) getBootTime() time.Time {
	data, err := os.ReadFile(filepath.Join(d.procPath, "uptime"))
	if err != nil {
		return time.Now()
	}

	// Parse uptime (seconds since boot)
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		if uptime, err := strconv.ParseFloat(fields[0], 64); err == nil {
			return time.Now().Add(-time.Duration(uptime) * time.Second)
		}
	}

	return time.Now()
}

// detectRuntimeType detects the container runtime type
func (d *ProcDiscoverer) detectRuntimeType(containerID, cmdline string) string {
	if strings.Contains(cmdline, runtimeTypeDocker) {
		return runtimeTypeDocker
	}
	if strings.Contains(cmdline, "containerd") {
		return "containerd"
	}
	if strings.Contains(cmdline, "cri-o") {
		return "cri-o"
	}

	// Check by container ID pattern
	if len(containerID) == 12 {
		// Docker typically uses 12-char IDs
		return runtimeTypeDocker
	}

	return "unknown"
}

// Name returns the discoverer name
func (d *ProcDiscoverer) Name() string {
	return "proc"
}

// ParseContainerIDFromCgroup parses container ID from cgroup path
func ParseContainerIDFromCgroup(cgroupPath string) string {
	// Docker format: /docker/abc123...
	if idx := strings.Index(cgroupPath, "/docker/"); idx >= 0 {
		containerPart := cgroupPath[idx+8:]
		if slashIdx := strings.Index(containerPart, "/"); slashIdx > 0 {
			return containerPart[:slashIdx]
		}
		return containerPart
	}

	// Containerd format: cri-containerd-abc123...
	if strings.Contains(cgroupPath, "cri-containerd-") {
		parts := strings.Split(cgroupPath, "/")
		for _, part := range parts {
			if strings.HasPrefix(part, "cri-containerd-") {
				id := strings.TrimPrefix(part, "cri-containerd-")
				return strings.TrimSuffix(id, ".scope")
			}
		}
	}

	// Kubernetes pod format
	if strings.Contains(cgroupPath, "/pod") {
		// Extract from kubepods path
		re := regexp.MustCompile(`/pod[a-f0-9\-]+/([a-f0-9]+)`)
		matches := re.FindStringSubmatch(cgroupPath)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// GetCgroupIDFromInode gets cgroup ID from inode
func GetCgroupIDFromInode(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to get stat")
	}

	return stat.Ino, nil
}
