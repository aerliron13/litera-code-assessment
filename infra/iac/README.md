# Infrastructure as code

**Intentionally empty.** The brief rules out cloud deployment, so nothing here is built — this
directory exists to mark where infrastructure definitions belong, and
`infra/pipeline/azure-pipelines.yml` references the paths it would expect to find.

## What the pipeline expects here

The Deploy stage applies these three files by name:

| File | Purpose |
|---|---|
| `deployment.yaml` | The API `Deployment`. Image tag is substituted by the pipeline. |
| `service.yaml` | A `ClusterIP` `Service` in front of the pods. |
| `ingress.yaml` | TLS termination and host routing. |

## What those manifests would need to get right

Notes rather than code, because the decisions are the interesting part:

- **Probes.** `/health` is liveness only today. Readiness needs its own endpoint once the service
  has dependencies, or a rolling update will send traffic to a pod that cannot yet reach its
  audit store.
- **No secrets in the manifests.** `Jwt:SigningKey` comes from Key Vault through the Secrets Store
  CSI driver, bound with workload identity. The committed `appsettings.Development.json` holds a
  development-only signing key and a shared seed password; neither may exist in a deployed
  environment, and the pipeline has a placeholder step asserting that.
- **Run as non-root**, read-only root filesystem, all capabilities dropped,
  `allowPrivilegeEscalation: false`.
- **A `NetworkPolicy`** — default-deny egress, with explicit allowances. A service that evaluates
  attacker-influenced documents should not be able to make arbitrary outbound calls.
- **Resource requests and limits**, so one tenant's load cannot starve the node, and a
  `PodDisruptionBudget` so a node drain does not take the service down.
- **More than one replica.** The current `IMemoryCache` data layer makes that unsafe — each pod
  would hold its own approvals and its own audit trail — which is itself the clearest argument for
  the durable store described in [PRODUCTION_NOTES.md](../../PRODUCTION_NOTES.md).

## Beyond the cluster

Also absent, and needed before any of the above is real: Terraform or Bicep for the cluster, the
registry, Key Vault, the database and the append-only audit store, with per-environment state and
a plan/apply gate mirroring the pipeline's deployment approval.
