package veilwarden.authz

import rego.v1

default allow := true  # TEMP: allow all to debug

# TLS tunnel establishment
allow if input.method == "CONNECT"

# Anthropic API - allow all requests
allow if {
    input.host == "api.anthropic.com"
}

# Statsig (Claude Code telemetry)
allow if {
    input.host == "api.statsig.com"
}

# Sentry (error reporting)
allow if {
    endswith(input.host, ".sentry.io")
}

# Uncomment to allow additional services:

# GitHub API
# allow if {
#     input.host == "api.github.com"
#     input.method in ["GET", "POST", "PATCH", "PUT", "DELETE"]
# }

# npm registry
# allow if {
#     input.host == "registry.npmjs.org"
#     input.method == "GET"
# }
