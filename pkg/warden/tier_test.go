// pkg/warden/tier_test.go
package warden

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTierString(t *testing.T) {
	assert.Equal(t, "standard", TierStandard.String())
	assert.Equal(t, "permissive", TierPermissive.String())
}

func TestParseTier(t *testing.T) {
	tests := []struct {
		input    string
		expected Tier
		wantErr  bool
	}{
		{"standard", TierStandard, false},
		{"permissive", TierPermissive, false},
		{"", TierStandard, false}, // empty defaults to standard
		{"STANDARD", TierStandard, false}, // case insensitive
		{"invalid", TierStandard, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tier, err := ParseTier(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, tier)
			}
		})
	}
}

func TestTierIsPermissive(t *testing.T) {
	assert.False(t, TierStandard.IsPermissive())
	assert.True(t, TierPermissive.IsPermissive())
}
