# Veilwarden Policy Files

This directory contains Rego policies evaluated by OPA for authorization decisions.

## Policy Decision Point

Policies must define a decision at path `veilwarden/authz/allow` that returns a boolean.

## Input Structure

Policies receive the following input:

```json
{
  "method": "GET",
  "path": "/repos/user/repo",
  "query": "page=1",
  "upstream_host": "api.github.com",
  "agent_id": "cli-tool",
  "user_id": "alice",
  "user_email": "alice@example.com",
  "user_org": "engineering",
  "request_id": "abc123",
  "timestamp": "2025-11-16T12:00:00Z"
}
```

## Examples

See `example.rego` and `allow_all.rego` for sample policies.
