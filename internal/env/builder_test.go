package env

import (
	"strings"
	"testing"
)

func TestBuildProxyEnv_StripsSecrets(t *testing.T) {
	parentEnv := []string{
		"DOPPLER_TOKEN=dp.st.dev.secret123",
		"OPENAI_API_KEY=sk-test",
		"GITHUB_TOKEN=ghp_test",
		"AWS_SECRET_ACCESS_KEY=secret",
		"MY_PASSWORD=hunter2",
		"PATH=/usr/bin",
		"HOME=/home/user",
		"EDITOR=vim",
	}

	childEnv := BuildProxyEnv(parentEnv, "http://localhost:8080", "/tmp/ca.crt", nil)

	// Check what's stripped and what remains
	envMap := make(map[string]bool)
	for _, e := range childEnv {
		key := strings.SplitN(e, "=", 2)[0]
		envMap[key] = true
	}

	// These should be stripped (secrets)
	strippedVars := []string{"DOPPLER_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "MY_PASSWORD"}
	for _, v := range strippedVars {
		if envMap[v] {
			t.Errorf("%s should be stripped from child environment", v)
		}
	}

	// These should remain (non-secrets)
	remainingVars := []string{"PATH", "HOME", "EDITOR"}
	for _, v := range remainingVars {
		if !envMap[v] {
			t.Errorf("%s should remain in child environment", v)
		}
	}

	// Proxy vars should be added
	if !envMap["HTTP_PROXY"] {
		t.Fatal("HTTP_PROXY should be added to child environment")
	}
}

func TestBuildProxyEnv_Passthrough(t *testing.T) {
	parentEnv := []string{
		"OPENAI_API_KEY=sk-test",
		"CUSTOM_TOKEN=my-token",
		"PATH=/usr/bin",
	}

	// Allow CUSTOM_TOKEN through via passthrough
	childEnv := BuildProxyEnv(parentEnv, "http://localhost:8080", "/tmp/ca.crt", []string{"CUSTOM_TOKEN"})

	envMap := make(map[string]bool)
	for _, e := range childEnv {
		key := strings.SplitN(e, "=", 2)[0]
		envMap[key] = true
	}

	// CUSTOM_TOKEN should be allowed through
	if !envMap["CUSTOM_TOKEN"] {
		t.Error("CUSTOM_TOKEN should be allowed through via passthrough")
	}

	// OPENAI_API_KEY should still be stripped (not in passthrough)
	if envMap["OPENAI_API_KEY"] {
		t.Error("OPENAI_API_KEY should be stripped")
	}

	// PATH should remain
	if !envMap["PATH"] {
		t.Error("PATH should remain")
	}
}
