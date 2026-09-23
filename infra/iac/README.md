# Infrastructure as code

The Kubernetes manifests the pipeline applies. **Illustrative** — cloud deployment is outside the
brief, so none of this has been applied to a cluster, and every `REPLACE_ME` needs supplying.

| File | Purpose |
|---|---|
| `serviceaccount.yaml` | The workload identity. Bound to no Role; the token is not even mounted. |
| `networkpolicy.yaml` | Default-deny ingress and egress. |
| `deployment.yaml` | The API `Deployment`, hardened; image tag substituted by the pipeline. |
| `service.yaml` | `ClusterIP` in front of the pods. |
| `ingress.yaml` | TLS termination, host routing, rate limiting, body size. |

Applied in that order by the Deploy stage, so the service account and the policy exist before the
pods that depend on them.

## The decisions worth asking about

**One replica, and that is a defect rather than a choice.** The data layer is `IMemoryCache`, so
every pod holds its own approvals and its own audit trail. At two replicas an approver could record
an approval on pod A, the workflow run referencing it lands on pod B, and the action is refused as
unapproved — or a tenant's audit trail ends up split across pods with neither copy complete. This
is the clearest concrete argument for the durable stores in
[PRODUCTION_NOTES.md](../../PRODUCTION_NOTES.md). Until those exist this must not be scaled, which
is why there is no `HorizontalPodAutoscaler`, and why there is no `PodDisruptionBudget` either — at
one replica it could only block node drains, not preserve availability.

**Egress is default-deny, and that is the injection control.** This service evaluates documents a
vendor or tenant supplied, one of which is deliberately hostile. If injected content ever does
influence what the service *does*, the damage is bounded by what the pod can reach — and
exfiltrating a tenant's evidence needs somewhere to send it. Only DNS is allowed today. Each future
dependency gets its own rule rather than a widening of the policy.

**No secrets in these files.** `Jwt__SigningKey` and `Jwt__SeedUserPassword` come from a `Secret`
that a real deployment projects from Key Vault through the Secrets Store CSI driver, bound with
workload identity. The double underscore is how ASP.NET Core binds nested configuration, so
`Jwt__SigningKey` lands on `Jwt:SigningKey` — the same value `JwtOptions.Validate()` checks at
startup, which means a pod given a missing or short key refuses to start. That is intended: a
service that boots with a weak signing key has failed in the wrong direction.

The image also deletes `appsettings.Development.json` at build time, so the development signing key
cannot ship even if `ASPNETCORE_ENVIRONMENT` is set wrongly.

**Probes are honest about what they check.** All three point at `/health`, which reports that the
process is answering — not that it can reach anything. That is accurate while the data layer is
in-process, and becomes wrong the moment there is a real audit store, at which point readiness needs
its own endpoint. A rolling update that sends traffic to a pod which cannot write an audit event is
worse than one that waits.

**A memory limit but no CPU limit.** The request reserves capacity; CFS throttling on a
request-serving process turns a busy moment into latency spikes, and the namespace quota is the
right place to bound the blast radius.

**Swagger is not routed.** The ingress forwards `/api` only. An endpoint-and-payload inventory is
useful in development and is reconnaissance in production.

## Still absent

Terraform or Bicep for the cluster, the registry, Key Vault, the database and the append-only audit
store — with per-environment state and a plan/apply gate mirroring the pipeline's deployment
approval. Also the `Secret` itself, which by design is created by the platform rather than committed
here.
