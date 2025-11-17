package main

// k8sIdentity represents an authenticated Kubernetes workload.
type k8sIdentity struct {
	namespace      string
	serviceAccount string
	podName        string // May be empty if not available
	username       string // Full username: system:serviceaccount:NS:SA
}

// Type returns the identity type.
func (i *k8sIdentity) Type() string {
	return "kubernetes"
}

// Attributes returns the identity attributes as a map.
func (i *k8sIdentity) Attributes() map[string]string {
	attrs := map[string]string{
		"namespace":       i.namespace,
		"service_account": i.serviceAccount,
		"username":        i.username,
	}
	if i.podName != "" {
		attrs["pod_name"] = i.podName
	}
	return attrs
}

// PolicyInput returns the input map for OPA policy evaluation.
func (i *k8sIdentity) PolicyInput() map[string]interface{} {
	input := map[string]interface{}{
		"namespace":       i.namespace,
		"service_account": i.serviceAccount,
		"username":        i.username,
	}
	if i.podName != "" {
		input["pod_name"] = i.podName
	}
	return input
}
