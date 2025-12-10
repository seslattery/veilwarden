package warden

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/template"
)

//go:embed seatbelt.sbpl.tmpl
var seatbeltTemplate string

type profileData struct {
	DeniedReadLiterals   []string
	DeniedReadPatterns   []string
	AllowedWriteLiterals []string
	AllowedWritePatterns []string
	AllowedUnixSockets   []string
	ProxyPort            int
	EnablePTY            bool

	// Home directory dotfile protection
	HomeDir                 string   // e.g., /Users/sean
	DotfileReadExceptions   []string // Paths that are allowed to read despite being dotfiles
}

func generateSeatbeltProfile(cfg *Config) (string, error) {
	data, err := buildProfileData(cfg)
	if err != nil {
		return "", err
	}

	tmpl, err := template.New("seatbelt").Parse(seatbeltTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

func buildProfileData(cfg *Config) (*profileData, error) {
	// TODO: cfg.AllowedReadPaths is not yet implemented. Currently, the workaround
	// is to add paths to AllowedWritePaths, which grants read access via
	// DotfileReadExceptions for home directory dotfiles.
	data := &profileData{
		AllowedUnixSockets: cfg.AllowedUnixSockets,
		EnablePTY:          cfg.EnablePTY,
	}

	// Get home directory for dotfile protection
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	data.HomeDir = homeDir

	// Extract proxy port
	_, portStr, err := net.SplitHostPort(cfg.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy port: %w", err)
	}
	data.ProxyPort = port

	// Process denied read paths
	for _, p := range cfg.DeniedReadPaths {
		expanded := expandHome(p)
		if err := validatePathSafety(expanded, false); err != nil {
			return nil, fmt.Errorf("denied_read_paths: %w", err)
		}

		if isGlob(expanded) {
			regex, err := globToRegex(expanded)
			if err != nil {
				return nil, err
			}
			data.DeniedReadPatterns = append(data.DeniedReadPatterns, regex)
		} else {
			data.DeniedReadLiterals = append(data.DeniedReadLiterals, expanded)
		}
	}

	// Process allowed write paths
	for _, p := range cfg.AllowedWritePaths {
		expanded := expandHome(p)
		if err := validatePathSafety(expanded, true); err != nil {
			return nil, fmt.Errorf("allowed_write_paths: %w", err)
		}

		if isGlob(expanded) {
			regex, err := globToRegex(expanded)
			if err != nil {
				return nil, err
			}
			data.AllowedWritePatterns = append(data.AllowedWritePatterns, regex)
		} else {
			data.AllowedWriteLiterals = append(data.AllowedWriteLiterals, expanded)
		}

		// If this is a home directory dotfile, add it as an exception
		if isHomeDotfile(expanded, homeDir) {
			data.DotfileReadExceptions = append(data.DotfileReadExceptions, expanded)
		}
	}

	return data, nil
}

// isHomeDotfile checks if a path is a dotfile/dotdir in the home directory
func isHomeDotfile(path, homeDir string) bool {
	if !strings.HasPrefix(path, homeDir+"/") {
		return false
	}
	// Get the relative path after home directory
	rel := strings.TrimPrefix(path, homeDir+"/")
	// Check if it starts with a dot
	return strings.HasPrefix(rel, ".")
}
