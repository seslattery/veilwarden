// pkg/warden/tier.go
package warden

import (
	"fmt"
	"strings"
)

// Tier represents a sandbox security tier.
type Tier int

const (
	// TierStandard is the default secure tier with move-blocking,
	// dotfile protection, and limited mach services.
	TierStandard Tier = iota

	// TierPermissive relaxes restrictions for Docker, OAuth,
	// and complex environment compatibility.
	TierPermissive

	// TierParanoid is the most restrictive tier with deny-by-default
	// file reads. Only system paths, working directory, and explicitly
	// allowed paths can be read.
	TierParanoid
)

// String returns the string representation of a tier.
func (t Tier) String() string {
	switch t {
	case TierStandard:
		return "standard"
	case TierPermissive:
		return "permissive"
	case TierParanoid:
		return "paranoid"
	default:
		return "unknown"
	}
}

// IsPermissive returns true if this is the permissive tier.
func (t Tier) IsPermissive() bool {
	return t == TierPermissive
}

// IsParanoid returns true if this is the paranoid tier.
func (t Tier) IsParanoid() bool {
	return t == TierParanoid
}

// ParseTier parses a tier string. Empty string defaults to standard.
func ParseTier(s string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "standard":
		return TierStandard, nil
	case "permissive":
		return TierPermissive, nil
	case "paranoid":
		return TierParanoid, nil
	default:
		return TierStandard, fmt.Errorf("unknown tier: %q (valid: standard, permissive, paranoid)", s)
	}
}

// ValidTiers is a map of valid tier names for validation.
var ValidTiers = map[string]bool{
	"standard":   true,
	"permissive": true,
	"paranoid":   true,
	"":           true, // empty defaults to standard
}
