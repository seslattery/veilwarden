# VeilWarden laptop policy example
# Copy to ~/.veilwarden/policies/ and customize

package veilwarden.authz

# Default deny all requests
default allow := false

# Allow OpenAI API
allow if {
    input.upstream_host == "api.openai.com"
    input.method in ["GET", "POST"]
}

# Allow Anthropic API
allow if {
    input.upstream_host == "api.anthropic.com"
    input.method in ["GET", "POST"]
}

# Allow GitHub API (read-only)
allow if {
    input.upstream_host == "api.github.com"
    input.method in ["GET", "HEAD"]
}

# Block DELETE operations globally
deny if {
    input.method == "DELETE"
}
