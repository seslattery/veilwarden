package veilwarden.authz

import rego.v1

# Kubernetes Workload Identity Policy Examples
#
# This file demonstrates OPA policies for Kubernetes Service Account-based
# authorization. Policies evaluate requests using workload identity attributes:
#   - namespace: Kubernetes namespace
#   - service_account: ServiceAccount name
#   - pod_name: Pod name (if available)
#   - upstream_host: Target API endpoint
#   - method: HTTP method (GET, POST, etc.)

# Default deny all requests
default allow := false

# =============================================================================
# Pattern 1: Namespace-Based Access Control
# =============================================================================
# Only production namespace can access production APIs

# Allow production namespace to access Stripe API
allow if {
    input.namespace == "production"
    input.upstream_host == "api.stripe.com"
}

# Allow staging namespace to access Stripe test API
allow if {
    input.namespace == "staging"
    input.upstream_host == "api.stripe.com"
    startswith(input.path, "/v1/test/")
}

# =============================================================================
# Pattern 2: Service Account-Based Access Control
# =============================================================================
# Specific service accounts get access to specific APIs

# GitHub Actions CI/CD pipeline can access GitHub API
allow if {
    input.service_account == "github-actions"
    input.upstream_host == "api.github.com"
}

# Billing service can access Stripe API
allow if {
    input.service_account == "billing-service"
    input.upstream_host == "api.stripe.com"
}

# Email service can access SendGrid API
allow if {
    input.service_account == "email-service"
    input.upstream_host == "api.sendgrid.com"
}

# =============================================================================
# Pattern 3: Method-Based Restrictions
# =============================================================================
# Limit certain service accounts to read-only access

# Analytics service can only read from APIs
allow if {
    input.service_account == "analytics"
    input.method in ["GET", "HEAD", "OPTIONS"]
}

# Data pipeline can write to data warehouse
allow if {
    input.service_account == "data-pipeline"
    input.upstream_host == "api.snowflake.com"
    input.method in ["GET", "POST", "PUT"]
}

# =============================================================================
# Pattern 4: Path-Based Access Control
# =============================================================================
# Restrict access to specific API endpoints

# Customer service can only access customer-related endpoints
allow if {
    input.service_account == "customer-service"
    input.upstream_host == "api.stripe.com"
    startswith(input.path, "/v1/customers/")
}

# Payment service can access both customers and charges
allow if {
    input.service_account == "payment-service"
    input.upstream_host == "api.stripe.com"
    paths := ["/v1/customers/", "/v1/charges/", "/v1/payment_intents/"]
    some prefix in paths
    startswith(input.path, prefix)
}

# =============================================================================
# Pattern 5: Multi-Namespace Policies
# =============================================================================
# Allow certain namespaces broader access

# All namespaces can access public APIs
allow if {
    public_apis := ["api.github.com", "api.ipify.org", "httpbin.org"]
    input.upstream_host in public_apis
    input.method in ["GET", "HEAD"]
}

# Development and staging namespaces can access test environments
allow if {
    input.namespace in ["development", "staging"]
    test_hosts := ["api.stripe.com", "api.twilio.com"]
    input.upstream_host in test_hosts
    contains(input.path, "/test/")
}

# =============================================================================
# Pattern 6: Time-Based Access Control
# =============================================================================
# Restrict access based on time of day (batch jobs)

# Batch jobs only run during off-hours (UTC)
allow if {
    input.service_account == "nightly-batch"
    hour := time.clock(time.now_ns())[0]
    hour >= 22  # After 10 PM UTC
}

allow if {
    input.service_account == "nightly-batch"
    hour := time.clock(time.now_ns())[0]
    hour <= 6   # Before 6 AM UTC
}

# =============================================================================
# Pattern 7: Combined Conditions
# =============================================================================
# Require multiple conditions to be met

# CI/CD can create GitHub releases only from production namespace
allow if {
    input.namespace == "production"
    input.service_account == "release-automation"
    input.upstream_host == "api.github.com"
    input.method == "POST"
    contains(input.path, "/releases")
}

# Monitoring service can read metrics from any API
allow if {
    input.service_account == "monitoring"
    input.method == "GET"
    endpoints_with_monitoring := ["api.stripe.com", "api.github.com", "api.datadog.com"]
    input.upstream_host in endpoints_with_monitoring
    regex.match(`/(metrics|health|status)`, input.path)
}

# =============================================================================
# Pattern 8: Deny Rules (Explicit Denials)
# =============================================================================
# Use helper rules to explicitly deny dangerous operations

# Never allow deletion of production resources (defense in depth)
deny_reasons contains "production resources cannot be deleted" if {
    input.namespace == "production"
    input.method == "DELETE"
}

# Block access to sensitive endpoints
deny_reasons contains "access to admin endpoints denied" if {
    contains(input.path, "/admin")
    not input.service_account == "admin-console"
}

# Override allow if any deny reason exists
default allow := false

allow if {
    # Must pass allow rules
    allow_rules
    # Must not trigger deny rules
    count(deny_reasons) == 0
}

# Helper: collect all allow rules (replace inline allow rules with this pattern)
allow_rules if {
    # Reference specific allow rules by pattern
    true  # Placeholder - in production, use specific rule references
}

# =============================================================================
# Pattern 9: Audit Logging Hints
# =============================================================================
# Provide hints for audit logging (consumed by veilwarden)

audit_metadata := {
    "namespace": input.namespace,
    "service_account": input.service_account,
    "upstream_host": input.upstream_host,
    "risk_level": risk_level,
}

# Calculate risk level based on operation
risk_level := "high" if {
    input.method in ["DELETE", "PUT", "PATCH"]
    input.namespace == "production"
}

risk_level := "medium" if {
    input.method == "POST"
}

risk_level := "low" if {
    input.method in ["GET", "HEAD", "OPTIONS"]
}

# =============================================================================
# Pattern 10: Testing Helpers
# =============================================================================
# Helper rules for policy testing

# List of all service accounts mentioned in policies (for testing)
known_service_accounts := {
    "github-actions",
    "billing-service",
    "email-service",
    "analytics",
    "data-pipeline",
    "customer-service",
    "payment-service",
    "nightly-batch",
    "release-automation",
    "monitoring",
    "admin-console",
}

# List of all upstream hosts mentioned in policies (for testing)
known_upstream_hosts := {
    "api.stripe.com",
    "api.github.com",
    "api.sendgrid.com",
    "api.snowflake.com",
    "api.ipify.org",
    "httpbin.org",
    "api.twilio.com",
    "api.datadog.com",
}

# =============================================================================
# Production Example: Complete Policy for a Multi-Tenant System
# =============================================================================

# Tenant isolation: each namespace can only access its own tenant data
allow if {
    # Extract tenant ID from namespace (e.g., "tenant-acme-corp")
    startswith(input.namespace, "tenant-")
    tenant_id := trim_prefix(input.namespace, "tenant-")

    # Ensure path contains tenant ID
    contains(input.path, tenant_id)

    # Allow access to tenant-specific API
    input.upstream_host == "api.example.com"
}

# Platform services (non-tenant namespaces) have broader access
allow if {
    input.namespace in ["platform-services", "infrastructure"]
    input.service_account == "platform-api"
    input.upstream_host in ["api.example.com", "api.stripe.com"]
}

# =============================================================================
# Helper Functions
# =============================================================================

# Check if request is from a CI/CD service account
is_ci_service_account if {
    ci_accounts := ["github-actions", "gitlab-runner", "jenkins"]
    input.service_account in ci_accounts
}

# Check if upstream host is a production environment
is_production_api if {
    not contains(input.upstream_host, "test")
    not contains(input.upstream_host, "staging")
    not contains(input.upstream_host, "dev")
}

# Check if request is read-only
is_read_only if {
    input.method in ["GET", "HEAD", "OPTIONS"]
}
