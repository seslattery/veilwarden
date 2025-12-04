package warden

import "strings"

// globToRegex converts a glob pattern to a regex pattern for SBPL.
func globToRegex(pattern string) (string, error) {
	var buf strings.Builder
	buf.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				// ** matches anything including /
				buf.WriteString(".*")
				i++
			} else {
				// * matches anything except /
				buf.WriteString("[^/]*")
			}
		case '?':
			// ? matches single char except /
			buf.WriteString("[^/]")
		case '.', '+', '^', '$', '|', '(', ')', '[', ']', '\\':
			// Escape regex metacharacters
			buf.WriteByte('\\')
			buf.WriteByte(pattern[i])
		default:
			buf.WriteByte(pattern[i])
		}
	}

	buf.WriteString("$")
	return buf.String(), nil
}
