package warden

// ParanoidSystemPaths returns the default system paths that are readable
// in paranoid tier. These are essential for program execution.
func ParanoidSystemPaths() []string {
	return []string{
		"/usr",         // Binaries, libraries
		"/bin",         // Core binaries
		"/sbin",        // System binaries
		"/opt",         // Homebrew, optional packages
		"/var",         // System state (symlink to /private/var)
		"/private/var", // Actual /var location
		"/etc",         // System config (symlink to /private/etc)
		"/private/etc", // Actual /etc location
		"/System",      // macOS system files
		"/nix",         // Nix package manager (if present)
		"/Applications", // App bundles (Xcode CLT, etc.)
		"/Library",     // System-wide libraries/frameworks
		"/dev",         // Device files
		"/private/tmp", // Temp directory (actual location)
		"/tmp",         // Temp directory (symlink)
	}
}
