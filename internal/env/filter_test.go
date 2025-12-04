package env

import "testing"

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		key      string
		isSecret bool
	}{
		{"OPENAI_API_KEY", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"GITHUB_TOKEN", true},
		{"DOPPLER_TOKEN", true},
		{"MY_PASSWORD", true},
		{"DB_CREDENTIALS", true},
		{"PRIVATE_KEY", true},
		{"AUTH_TOKEN", true},
		{"PATH", false},
		{"HOME", false},
		{"EDITOR", false},
		{"DEBUG", false},
		{"NODE_ENV", false},
		{"GOPATH", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := LooksLikeSecret(tt.key)
			if result != tt.isSecret {
				t.Errorf("LooksLikeSecret(%q) = %v, want %v", tt.key, result, tt.isSecret)
			}
		})
	}
}
