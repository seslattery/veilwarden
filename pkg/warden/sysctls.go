// pkg/warden/sysctls.go
package warden

// StandardSysctlAllowlist returns sysctls allowed in standard tier.
// Based on Claude Code and Codex allowlists.
func StandardSysctlAllowlist() []string {
	return []string{
		// Hardware info
		"hw.activecpu",
		"hw.busfrequency_compat",
		"hw.byteorder",
		"hw.cacheconfig",
		"hw.cachelinesize_compat",
		"hw.cpufamily",
		"hw.cpufrequency",
		"hw.cpufrequency_compat",
		"hw.cputype",
		"hw.l1dcachesize_compat",
		"hw.l1icachesize_compat",
		"hw.l2cachesize_compat",
		"hw.l3cachesize_compat",
		"hw.logicalcpu",
		"hw.logicalcpu_max",
		"hw.machine",
		"hw.memsize",
		"hw.ncpu",
		"hw.nperflevels",
		"hw.packages",
		"hw.pagesize",
		"hw.pagesize_compat",
		"hw.physicalcpu",
		"hw.physicalcpu_max",
		"hw.tbfrequency_compat",
		"hw.vectorunit",

		// Kernel info
		"kern.argmax",
		"kern.bootargs",
		"kern.hostname",
		"kern.maxfiles",
		"kern.maxfilesperproc",
		"kern.maxproc",
		"kern.ngroups",
		"kern.osproductversion",
		"kern.osrelease",
		"kern.ostype",
		"kern.osvariant_status",
		"kern.osversion",
		"kern.secure_kernel",
		"kern.tcsm_available",
		"kern.tcsm_enable",
		"kern.usrstack64",
		"kern.version",
		"kern.willshutdown",

		// CPU brand
		"machdep.cpu.brand_string",
		"machdep.ptrauth_enabled",

		// Security
		"security.mac.lockdown_mode_state",

		// Process
		"sysctl.proc_cputype",

		// VM
		"vm.loadavg",
	}
}

// StandardSysctlPrefixes returns sysctl prefixes allowed in standard tier.
func StandardSysctlPrefixes() []string {
	return []string{
		"hw.optional.arm",
		"hw.optional.arm.",
		"hw.optional.armv8_",
		"hw.perflevel",
		"kern.proc.all",
		"kern.proc.pgrp.",
		"kern.proc.pid.",
		"machdep.cpu.",
		"net.routetable.",
	}
}
