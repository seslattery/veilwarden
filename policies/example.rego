package veilwarden.authz

import rego.v1

# Default deny
default allow := false

# Allow GET requests for engineering users
allow if {
    input.method == "GET"
    input.user_org == "engineering"
}

# Allow POST to GitHub API for specific agents
allow if {
    input.method == "POST"
    input.upstream_host == "api.github.com"
    input.agent_id == "ci-agent"
}

# Allow all requests from admin users
allow if {
    endswith(input.user_email, "@admin.example.com")
}

# Deny DELETE operations on production hosts
allow if {
    input.method != "DELETE"
    input.upstream_host != "api.stripe.com"
}
