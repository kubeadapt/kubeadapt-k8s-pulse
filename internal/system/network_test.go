package system

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetNetworkInterfaces tests network interface enumeration
func TestGetNetworkInterfaces(t *testing.T) {
	// Call the real function
	interfaces, err := GetNetworkInterfaces()

	// Should not error on any normal system
	require.NoError(t, err, "GetNetworkInterfaces() should not error")

	// Should return at least one UP interface (usually lo or eth0)
	require.NotEmpty(t, interfaces, "Should have at least one UP interface")

	// Verify all returned interfaces are UP
	for _, iface := range interfaces {
		t.Logf("Found interface: %s (index %d, flags %v)",
			iface.Name, iface.Index, iface.Flags)

		// All returned interfaces should have the UP flag
		assert.True(t, iface.Flags&0x1 != 0,
			"Interface %s should be UP", iface.Name)

		// Index should be positive
		assert.Greater(t, iface.Index, 0,
			"Interface %s should have positive index", iface.Name)

		// Name should not be empty
		assert.NotEmpty(t, iface.Name,
			"Interface should have a name")
	}
}

// TestGetNetworkInterfacesFiltersDown tests that DOWN interfaces are filtered out
func TestGetNetworkInterfacesFiltersDown(t *testing.T) {
	// This test verifies the filtering logic by calling the real function
	// We can't mock DOWN interfaces, but we can verify the logic works

	interfaces, err := GetNetworkInterfaces()
	require.NoError(t, err)

	// All returned interfaces MUST be UP (this is the core filtering logic)
	for _, iface := range interfaces {
		// Verify UP flag is set (bit 0)
		isUp := iface.Flags&0x1 != 0
		assert.True(t, isUp,
			"Interface %s should be UP (all DOWN interfaces must be filtered)",
			iface.Name)
	}

	t.Logf("Successfully verified %d UP interfaces (DOWN interfaces filtered)",
		len(interfaces))
}

// TestNetworkInterfaceFields tests that all interface fields are populated correctly
func TestNetworkInterfaceFields(t *testing.T) {
	interfaces, err := GetNetworkInterfaces()
	require.NoError(t, err)
	require.NotEmpty(t, interfaces)

	for _, iface := range interfaces {
		// Test that all fields are properly populated
		t.Run(iface.Name, func(t *testing.T) {
			// Index must be positive
			assert.Greater(t, iface.Index, 0,
				"Index should be positive")

			// Name must not be empty
			assert.NotEmpty(t, iface.Name,
				"Name should not be empty")

			// Flags should be set (at minimum, UP flag)
			assert.NotZero(t, iface.Flags,
				"Flags should be set")

			// Should have UP flag since we filtered DOWN interfaces
			assert.NotZero(t, iface.Flags&0x1,
				"Should have UP flag")
		})
	}
}

// TestCommonInterfaceNames tests for common interface names
func TestCommonInterfaceNames(t *testing.T) {
	interfaces, err := GetNetworkInterfaces()
	require.NoError(t, err)

	// Check if we have some common interface names
	// This is not a requirement, just informational
	commonNames := map[string]bool{
		"lo":      false, // loopback
		"eth0":    false, // ethernet
		"en0":     false, // macOS ethernet
		"wlan":    false, // wireless (any wlan*)
		"docker0": false, // docker bridge
	}

	for _, iface := range interfaces {
		if _, exists := commonNames[iface.Name]; exists {
			commonNames[iface.Name] = true
			t.Logf("Found common interface: %s", iface.Name)
		}
		// Check for partial matches (e.g., wlan0, wlan1)
		if len(iface.Name) >= 4 && iface.Name[:4] == "wlan" {
			commonNames["wlan"] = true
			t.Logf("Found wireless interface: %s", iface.Name)
		}
	}

	// Log which common interfaces were found (informational only)
	for name, found := range commonNames {
		if found {
			t.Logf("Found common interface type: %s", name)
		}
	}
}

// TestLoopbackInterface tests for the presence of loopback interface
func TestLoopbackInterface(t *testing.T) {
	interfaces, err := GetNetworkInterfaces()
	require.NoError(t, err)

	// Look for loopback interface
	hasLoopback := false
	for _, iface := range interfaces {
		if iface.Name == "lo" || iface.Name == "lo0" {
			hasLoopback = true
			t.Logf("Found loopback interface: %s (index %d)",
				iface.Name, iface.Index)
			break
		}
	}

	// Most systems should have a loopback interface
	// This is informational - not a hard requirement
	if hasLoopback {
		t.Log("Loopback interface is UP")
	} else {
		t.Log("No loopback interface found (may be DOWN or have different name)")
	}
}
