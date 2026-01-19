// pkg/warden/mach_services_test.go
package warden

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStandardMachServices(t *testing.T) {
	services := StandardMachServices()

	// Should have core services
	assert.Contains(t, services, "com.apple.system.opendirectoryd.libinfo")
	assert.Contains(t, services, "com.apple.fonts")
	assert.Contains(t, services, "com.apple.trustd.agent")

	// Should NOT have auth services
	assert.NotContains(t, services, "com.apple.security.agent")
	assert.NotContains(t, services, "com.apple.CoreAuthentication.agent")
	assert.NotContains(t, services, "com.apple.accountsd")

	// Should have exactly 14 services
	assert.Len(t, services, 14)
}

func TestPermissiveMachServices(t *testing.T) {
	services := PermissiveMachServices()

	// Should have all standard services
	for _, s := range StandardMachServices() {
		assert.Contains(t, services, s)
	}

	// Should also have auth services
	assert.Contains(t, services, "com.apple.security.agent")
	assert.Contains(t, services, "com.apple.CoreAuthentication.agent")
	assert.Contains(t, services, "com.apple.accountsd")

	// Should have 23 services
	assert.Len(t, services, 23)
}

func TestMachServicesForTier(t *testing.T) {
	standard := MachServicesForTier(TierStandard)
	permissive := MachServicesForTier(TierPermissive)

	assert.Len(t, standard, 14)
	assert.Len(t, permissive, 23)
}
