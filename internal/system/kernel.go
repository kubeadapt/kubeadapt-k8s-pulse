package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	kernelVersion     KernelVersion
	kernelVersionOnce sync.Once
	kernelVersionErr  error
)

// KernelVersion represents a Linux kernel version
type KernelVersion struct {
	Major int
	Minor int
	Patch int
}

// String returns the kernel version as a string
func (kv KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", kv.Major, kv.Minor, kv.Patch)
}

// IsAtLeast checks if the kernel version is at least the specified version
func (kv KernelVersion) IsAtLeast(major, minor int) bool {
	if kv.Major > major {
		return true
	}
	if kv.Major == major && kv.Minor >= minor {
		return true
	}
	return false
}

// GetKernelVersion returns the current kernel version
// Uses sync.Once to cache the result
func GetKernelVersion() (KernelVersion, error) {
	kernelVersionOnce.Do(func() {
		kernelVersion, kernelVersionErr = detectKernelVersion()
	})
	return kernelVersion, kernelVersionErr
}

// detectKernelVersion detects the Linux kernel version
func detectKernelVersion() (KernelVersion, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return KernelVersion{}, fmt.Errorf("failed to get uname: %w", err)
	}

	// Convert Release to string
	// Release format: "5.15.0-89-generic" or "6.1.0"
	release := string(uname.Release[:])
	// Remove null terminator
	if idx := strings.IndexByte(release, 0); idx != -1 {
		release = release[:idx]
	}

	// Parse version string
	// Split by '-' first to remove distribution-specific suffix
	parts := strings.Split(release, "-")
	if len(parts) == 0 {
		return KernelVersion{}, fmt.Errorf("invalid kernel release format: %s", release)
	}

	// Parse major.minor.patch
	versionParts := strings.Split(parts[0], ".")
	if len(versionParts) < 2 {
		return KernelVersion{}, fmt.Errorf("invalid kernel version format: %s", parts[0])
	}

	major, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return KernelVersion{}, fmt.Errorf("invalid major version: %s", versionParts[0])
	}

	minor, err := strconv.Atoi(versionParts[1])
	if err != nil {
		return KernelVersion{}, fmt.Errorf("invalid minor version: %s", versionParts[1])
	}

	patch := 0
	if len(versionParts) >= 3 {
		patch, _ = strconv.Atoi(versionParts[2])
		// Ignore error for patch version as it's optional
	}

	return KernelVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
}

// SupportsLookupAndDelete returns true if the kernel supports atomic LookupAndDelete
// This operation was added in kernel 5.6
func SupportsLookupAndDelete() bool {
	kv, err := GetKernelVersion()
	if err != nil {
		// If we can't detect kernel version, assume it doesn't support it
		// This is a conservative fallback
		return false
	}

	return kv.IsAtLeast(5, 6)
}

// GetHostname returns the system hostname
func GetHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	return hostname, nil
}
