# Kubernetes scheduling evidence

The full and orchestration profiles read Kueue queues, resource flavors,
topologies, admission checks, quotas, priority classes, runtime classes, and
referenced controller configuration. The collector does not change cluster state.

The output distinguishes empty resources, absent APIs, forbidden reads, errors,
and incomplete inventories. Retention limits and request timeouts bound collection.
Secret-like configuration keys are redacted. Review collected infrastructure
metadata before sharing audit output.

The report includes scheduling findings and their scope. A placement restriction
does not prove a provider defect. The test suite runs the packaged collector with
a fake kubectl, merges its JSON, and verifies the rendered findings.
