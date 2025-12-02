package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMount_String(t *testing.T) {
	tests := []struct {
		name string
		m    Mount
		want string
	}{
		{
			name: "read-write mount",
			m:    Mount{HostPath: "/tmp/data", ContainerPath: "/data", ReadOnly: false},
			want: "/tmp/data:/data",
		},
		{
			name: "readonly mount",
			m:    Mount{HostPath: "/usr/lib", ContainerPath: "/usr/lib", ReadOnly: true},
			want: "/usr/lib:/usr/lib:ro",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.m.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "valid config",
			cfg: &Config{
				Command:    []string{"python", "test.py"},
				Env:        []string{"PATH=/usr/bin"},
				Mounts:     []Mount{{HostPath: "/tmp", ContainerPath: "/tmp", ReadOnly: false}},
				WorkingDir: "/workspace",
			},
			wantErr: "",
		},
		{
			name: "empty command",
			cfg: &Config{
				Command: []string{},
				Env:     []string{},
			},
			wantErr: "command is required",
		},
		{
			name: "relative container path",
			cfg: &Config{
				Command: []string{"test"},
				Mounts:  []Mount{{HostPath: "/tmp", ContainerPath: "relative", ReadOnly: false}},
			},
			wantErr: "container path must be absolute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
