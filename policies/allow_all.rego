package veilwarden.authz

import rego.v1

# Allow all requests (useful for testing OPA integration)
default allow := true
