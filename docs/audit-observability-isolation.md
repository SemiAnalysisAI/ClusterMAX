# Observability tenant isolation

The full and security profiles discover metrics and dashboard query backends
from collected monitoring evidence and local sockets and process names.
Kubernetes audits also inspect Services in the selected kube context.
Slurm and standalone audits do not inspect an unrelated kube context.
Per-node exporters are inventory evidence, not tenant-isolation targets.

Set `CLUSTERMAX_OBS_TARGETS` to a comma-separated list of approved HTTP(S)
endpoints to bypass discovery. The CLI issues bounded read-only requests.
It does not run deletion operations or change backend configuration.
It verifies TLS certificates and refuses redirects.
Set `CMAX_OWN_NAMESPACE` to the audited tenant namespace when it is not `default`.

The command stores counts, booleans, platform names, and authentication schemes.
It does not store metric series, foreign tenant names, or credentials.
An unreachable endpoint or absent target does not establish isolation.
Visible shared infrastructure labels alone do not prove a tenant breach.
The result is evidence from the operator's current network vantage, not proof of
access from every tenant pod.

The bundled library supports caller-supplied credentials for controlled tests.
The CLI integration does not harvest credentials or try vendor defaults.
Review discovered targets and endpoint authorization before auditing a new environment.

All validation uses mocked requests or local fixture HTTP servers. No provider
endpoint was contacted while preparing this PR.
