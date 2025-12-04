package veilwarden.authz

import rego.v1

default allow := false

# TLS tunnel establishment
allow if input.method == "CONNECT"

# Anthropic API - messages endpoint (chat)
allow if {
    input.host == "api.anthropic.com"
    input.method == "POST"
    startswith(input.path, "/v1/messages")
}

# Anthropic API - model listing
allow if {
    input.host == "api.anthropic.com"
    input.method == "GET"
    input.path == "/v1/models"
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
