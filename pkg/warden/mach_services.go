// pkg/warden/mach_services.go
package warden

// StandardMachServices returns the mach services allowed in standard tier.
// These are the minimal services needed for normal development work.
func StandardMachServices() []string {
	return []string{
		// Core system services
		"com.apple.system.opendirectoryd.libinfo",
		"com.apple.system.opendirectoryd.membership",
		"com.apple.system.logger",
		"com.apple.system.notification_center",
		"com.apple.bsd.dirhelper",
		"com.apple.logd",

		// Services & UI
		"com.apple.lsd.mapdb",
		"com.apple.coreservices.launchservicesd",
		"com.apple.distributed_notifications@Uv3",

		// Fonts
		"com.apple.fonts",
		"com.apple.FontObjectsServer",

		// Security (TLS, not Keychain UI)
		"com.apple.securityd.xpc",
		"com.apple.trustd.agent",

		// Power (for sleep/wake handling)
		"com.apple.PowerManagement.control",

		// System Configuration (needed for DNS, network config - used by Rust system-configuration crate)
		"com.apple.SystemConfiguration.DNSConfiguration",
		"com.apple.SystemConfiguration.configd",
		"com.apple.analyticsd",
	}
}

// PermissiveMachServices returns the mach services allowed in permissive tier.
// Includes auth services for OAuth, Keychain, and additional system services.
func PermissiveMachServices() []string {
	// Start with standard services
	services := StandardMachServices()

	// Add auth services (OAuth, Keychain UI)
	authServices := []string{
		"com.apple.SecurityServer",
		"com.apple.security.agent",
		"com.apple.CoreAuthentication.agent",
		"com.apple.cfnetwork.AuthBrokerAgent",
		"com.apple.accountsd",
	}

	// Add additional system services
	additionalServices := []string{
		"com.apple.audio.systemsoundserver",
		"com.apple.sysmond",
	}

	services = append(services, authServices...)
	services = append(services, additionalServices...)

	return services
}

// MachServicesForTier returns the appropriate mach services for a tier.
func MachServicesForTier(tier Tier) []string {
	if tier.IsPermissive() {
		return PermissiveMachServices()
	}
	return StandardMachServices()
}
