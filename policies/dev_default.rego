package veilwarden.authz

import rego.v1

default allow := false

llm_hosts := {
  "api.anthropic.com",
  "api.openai.com",
  "generativelanguage.googleapis.com",
}

scm_hosts_ro := {
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
  "gitlab.com",
  "api.gitlab.com",
  "bitbucket.org",
  "dev.azure.com",
}

# Future: Hosts where we allow full read/write, from user config
# trusted_rw_hosts := { h | h := input.config.trusted_rw_hosts[_] }

# Future: Hosts where we allow more permissive reads (e.g. GET with body/auth)
# trusted_ro_hosts := { h | h := input.config.trusted_ro_hosts[_] }

method_is_read_only(method) if {
  method == "GET"
}

method_is_read_only(method) if {
  method == "HEAD"
}

has_body if {
  input.body != ""
}

# Future: Check for auth headers when headers are available in input
# has_auth_header if {
#   input.headers["authorization"] != ""
# }
# has_auth_header if {
#   input.headers["x-api-key"] != ""
# }

############################
# Allow rules
############################

# 1) Fully trusted hosts (LLM providers)
allow if {
  input.upstream_host in llm_hosts
}

# Future: Allow configured RW hosts
# allow if {
#   input.upstream_host in trusted_rw_hosts
# }

# 2) Source control + code hosting: read-only, no body
allow if {
  input.upstream_host in scm_hosts_ro
  method_is_read_only(input.method)
  not has_body
}

# Future: Trusted read-only hosts (user-configured)
# allow if {
#   input.upstream_host in trusted_ro_hosts
#   method_is_read_only(input.method)
# }

# 3) Everything else on the Internet:
#    GET/HEAD only, no body
#    Future: also check for no auth headers to prevent credential leakage
allow if {
  not (input.upstream_host in llm_hosts)
  not (input.upstream_host in scm_hosts_ro)
  # Future: not (input.upstream_host in trusted_rw_hosts)
  # Future: not (input.upstream_host in trusted_ro_hosts)

  method_is_read_only(input.method)
  not has_body
  # Future: not has_auth_header
}
