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

	// Should have Keychain services (for tools like Claude Code that store credentials)
	assert.Contains(t, services, "com.apple.SecurityServer")
	assert.Contains(t, services, "com.apple.security.agent")
	assert.Contains(t, services, "com.apple.CoreAuthentication.agent")

	// Should NOT have OAuth/account services (permissive only)
	assert.NotContains(t, services, "com.apple.accountsd")
	assert.NotContains(t, services, "com.apple.cfnetwork.AuthBrokerAgent")

	// Should have exactly 20 services
	assert.Len(t, services, 20)
}

func TestPermissiveMachServices(t *testing.T) {
	services := PermissiveMachServices()

	// Should have all standard services
	for _, s := range StandardMachServices() {
		assert.Contains(t, services, s)
	}

	// Should also have OAuth/account services (beyond standard Keychain)
	assert.Contains(t, services, "com.apple.cfnetwork.AuthBrokerAgent")
	assert.Contains(t, services, "com.apple.accountsd")

	// Should have additional system services
	assert.Contains(t, services, "com.apple.audio.systemsoundserver")
	assert.Contains(t, services, "com.apple.sysmond")

	// Should have 24 services (20 standard + 4 additional)
	assert.Len(t, services, 24)
}

func TestMachServicesForTier(t *testing.T) {
	standard := MachServicesForTier(TierStandard)
	permissive := MachServicesForTier(TierPermissive)

	assert.Len(t, standard, 20)
	assert.Len(t, permissive, 24)
}
