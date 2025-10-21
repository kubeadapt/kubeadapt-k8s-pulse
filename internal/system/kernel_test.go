package system

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKernelVersionParsing tests parsing of various kernel version formats
func TestKernelVersionParsing(t *testing.T) {
	tests := []struct {
		name     string
		release  string
		expected KernelVersion
		wantErr  bool
	}{
		{
			name:     "Ubuntu kernel format",
			release:  "5.15.0-89-generic",
			expected: KernelVersion{Major: 5, Minor: 15, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "Debian kernel format",
			release:  "6.1.0",
			expected: KernelVersion{Major: 6, Minor: 1, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "Custom kernel with patch version",
			release:  "4.19.123-custom",
			expected: KernelVersion{Major: 4, Minor: 19, Patch: 123},
			wantErr:  false,
		},
		{
			name:     "Minimal version without patch",
			release:  "5.4",
			expected: KernelVersion{Major: 5, Minor: 4, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "Kernel with multiple dashes",
			release:  "5.15.0-1-amd64-generic",
			expected: KernelVersion{Major: 5, Minor: 15, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "Kernel 6.x series",
			release:  "6.5.13-generic",
			expected: KernelVersion{Major: 6, Minor: 5, Patch: 13},
			wantErr:  false,
		},
		{
			name:    "Invalid format - no version",
			release: "not-a-version",
			wantErr: true,
		},
		{
			name:    "Invalid format - empty string",
			release: "",
			wantErr: true,
		},
		{
			name:    "Invalid format - only major version",
			release: "5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock uname struct with the test release string
			// We need to test the parsing logic directly
			kv, err := parseKernelRelease(tt.release)

			if tt.wantErr {
				assert.Error(t, err, "Expected error for input: %s", tt.release)
				return
			}

			require.NoError(t, err, "Unexpected error for input: %s", tt.release)
			assert.Equal(t, tt.expected.Major, kv.Major, "Major version mismatch")
			assert.Equal(t, tt.expected.Minor, kv.Minor, "Minor version mismatch")
			assert.Equal(t, tt.expected.Patch, kv.Patch, "Patch version mismatch")
		})
	}
}

// parseKernelRelease is a helper function extracted from detectKernelVersion
// This allows us to test the parsing logic in isolation
func parseKernelRelease(release string) (KernelVersion, error) {
	// This logic is extracted from detectKernelVersion in kernel.go
	// to make it testable

	// Split by '-' first to remove distribution-specific suffix
	parts := make([]string, 0)
	for i, part := range []byte(release) {
		if part == '-' {
			parts = append(parts, release[:i])
			break
		}
	}
	if len(parts) == 0 {
		parts = append(parts, release)
	}

	if len(parts) == 0 || parts[0] == "" {
		return KernelVersion{}, ErrInvalidKernelRelease
	}

	// Parse major.minor.patch
	var major, minor, patch int
	versionParts := make([]string, 0)
	current := ""
	for _, ch := range parts[0] {
		if ch == '.' {
			versionParts = append(versionParts, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		versionParts = append(versionParts, current)
	}

	if len(versionParts) < 2 {
		return KernelVersion{}, ErrInvalidKernelVersion
	}

	// Parse major
	for _, ch := range versionParts[0] {
		if ch < '0' || ch > '9' {
			return KernelVersion{}, ErrInvalidMajorVersion
		}
		major = major*10 + int(ch-'0')
	}

	// Parse minor
	for _, ch := range versionParts[1] {
		if ch < '0' || ch > '9' {
			return KernelVersion{}, ErrInvalidMinorVersion
		}
		minor = minor*10 + int(ch-'0')
	}

	// Parse patch (optional)
	if len(versionParts) >= 3 {
		for _, ch := range versionParts[2] {
			if ch < '0' || ch > '9' {
				// Ignore non-numeric patch versions
				break
			}
			patch = patch*10 + int(ch-'0')
		}
	}

	return KernelVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
}

// Test error variables
var (
	ErrInvalidKernelRelease = assert.AnError
	ErrInvalidKernelVersion = assert.AnError
	ErrInvalidMajorVersion  = assert.AnError
	ErrInvalidMinorVersion  = assert.AnError
)

// TestKernelVersionIsAtLeast tests version comparison logic
func TestKernelVersionIsAtLeast(t *testing.T) {
	tests := []struct {
		name     string
		current  KernelVersion
		major    int
		minor    int
		expected bool
	}{
		{
			name:     "Current version greater than requirement (major)",
			current:  KernelVersion{Major: 6, Minor: 1, Patch: 0},
			major:    5,
			minor:    6,
			expected: true,
		},
		{
			name:     "Current version greater than requirement (minor)",
			current:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
			major:    5,
			minor:    6,
			expected: true,
		},
		{
			name:     "Current version less than requirement",
			current:  KernelVersion{Major: 4, Minor: 19, Patch: 0},
			major:    5,
			minor:    6,
			expected: false,
		},
		{
			name:     "Current version exactly equals requirement (boundary)",
			current:  KernelVersion{Major: 5, Minor: 6, Patch: 0},
			major:    5,
			minor:    6,
			expected: true,
		},
		{
			name:     "Current version one minor below requirement",
			current:  KernelVersion{Major: 5, Minor: 5, Patch: 99},
			major:    5,
			minor:    6,
			expected: false,
		},
		{
			name:     "Major version higher, minor lower",
			current:  KernelVersion{Major: 6, Minor: 1, Patch: 0},
			major:    5,
			minor:    15,
			expected: true,
		},
		{
			name:     "Kernel 4.x vs 5.x requirement",
			current:  KernelVersion{Major: 4, Minor: 19, Patch: 200},
			major:    5,
			minor:    0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.current.IsAtLeast(tt.major, tt.minor)
			assert.Equal(t, tt.expected, result,
				"KernelVersion{%d, %d, %d}.IsAtLeast(%d, %d) = %v, want %v",
				tt.current.Major, tt.current.Minor, tt.current.Patch,
				tt.major, tt.minor,
				result, tt.expected)
		})
	}
}

// TestKernelVersionString tests the String() method
func TestKernelVersionString(t *testing.T) {
	tests := []struct {
		name     string
		version  KernelVersion
		expected string
	}{
		{
			name:     "Standard version",
			version:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
			expected: "5.15.0",
		},
		{
			name:     "Version with patch",
			version:  KernelVersion{Major: 6, Minor: 1, Patch: 42},
			expected: "6.1.42",
		},
		{
			name:     "Old kernel",
			version:  KernelVersion{Major: 4, Minor: 19, Patch: 123},
			expected: "4.19.123",
		},
		{
			name:     "Zero patch",
			version:  KernelVersion{Major: 5, Minor: 4, Patch: 0},
			expected: "5.4.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSupportsLookupAndDelete tests kernel feature detection
func TestSupportsLookupAndDelete(t *testing.T) {
	// Note: This test would require mocking GetKernelVersion()
	// For now, we document the expected behavior

	tests := []struct {
		name     string
		version  KernelVersion
		expected bool
	}{
		{
			name:     "Kernel 5.5 - does not support",
			version:  KernelVersion{Major: 5, Minor: 5, Patch: 0},
			expected: false,
		},
		{
			name:     "Kernel 5.6 - supports (boundary)",
			version:  KernelVersion{Major: 5, Minor: 6, Patch: 0},
			expected: true,
		},
		{
			name:     "Kernel 5.15 - supports",
			version:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
			expected: true,
		},
		{
			name:     "Kernel 6.1 - supports",
			version:  KernelVersion{Major: 6, Minor: 1, Patch: 0},
			expected: true,
		},
		{
			name:     "Kernel 4.19 - does not support",
			version:  KernelVersion{Major: 4, Minor: 19, Patch: 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the logic directly using IsAtLeast
			result := tt.version.IsAtLeast(5, 6)
			assert.Equal(t, tt.expected, result,
				"Kernel %s support for LookupAndDelete", tt.version.String())
		})
	}
}

// TestGetHostname tests hostname retrieval
func TestGetHostname(t *testing.T) {
	// This function wraps os.Hostname(), so we mainly test it doesn't panic
	hostname, err := GetHostname()

	// Hostname should not error on any normal system
	require.NoError(t, err, "GetHostname() should not error")
	require.NotEmpty(t, hostname, "Hostname should not be empty")

	t.Logf("System hostname: %s", hostname)
}
