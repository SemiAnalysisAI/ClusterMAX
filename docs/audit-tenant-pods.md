# Tenant pod defaults

The full and orchestration profiles test an ordinary GPU pod and a tuned pod
in the tenant namespace. The security profile does not create these pods.
The check measures memlock, shared memory, capabilities, RDMA devices, and GDRCopy.
The tuned pod requests `IPC_LOCK`, shared memory, and an RDMA resource when available.
Both pods are removed after collection.

`CLUSTERMAX_AUDIT_TENANT_NAMESPACE` selects the tenant namespace. It defaults to
`default`, not the privileged namespace used by host checks. A namespace with a
privileged Pod Security profile cannot establish ordinary tenant admission behavior.
An unreadable namespace policy leaves admission acceptance unknown.
Permission errors, timeouts, and malformed responses do not establish a pass.
`namespaceEnforcesPrivileged` is `null` when the policy cannot be read.
Measured warnings retain priority over that unknown policy in the aggregate result.
`CLUSTERMAX_AUDIT_TENANT_POD_CHECK=0` disables this check.

Findings are warnings. A failed or unavailable probe does not prove that devices
are absent. Device warnings also require host evidence that the device applies.
Tests use fixed local fixtures and mocks. They do not contact a provider cluster.
