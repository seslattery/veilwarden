// pkg/warden/sysctls_test.go
package warden

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStandardSysctlAllowlist(t *testing.T) {
	sysctls := StandardSysctlAllowlist()

	// Should have common sysctls
	assert.Contains(t, sysctls, "hw.ncpu")
	assert.Contains(t, sysctls, "hw.memsize")
	assert.Contains(t, sysctls, "kern.osversion")

	// Should have at least 35 entries
	assert.GreaterOrEqual(t, len(sysctls), 35)
}

func TestStandardSysctlPrefixes(t *testing.T) {
	prefixes := StandardSysctlPrefixes()

	// Should have ARM-related prefixes
	assert.Contains(t, prefixes, "hw.optional.arm.")
	assert.Contains(t, prefixes, "hw.perflevel")
}
