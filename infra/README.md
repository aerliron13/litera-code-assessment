# infra

Delivery and infrastructure definitions.

```
infra/
  pipeline/
    azure-pipelines.yml    Build -> Test -> Package -> Deploy
  iac/
    serviceaccount.yaml    workload identity, no Role, token not mounted
    networkpolicy.yaml     default-deny ingress and egress
    deployment.yaml        the API Deployment, hardened
    service.yaml           ClusterIP
    ingress.yaml           TLS, routing, rate limiting
    README.md              the decisions worth asking about
```

The container build lives with the project it builds, at
[`src/RegulatedAi.Api/Dockerfile`](../src/RegulatedAi.Api/Dockerfile).

## Status

**Illustrative.** The brief excludes cloud deployment, so none of this has been applied to a
cluster and every value marked `REPLACE_ME` needs supplying. It is here to show the shape of the
delivery path — and, more usefully in a review, where the controls sit in it.

## The delivery path

| Stage | Runs on | Does |
|---|---|---|
| **Build** | every PR and `main` | Restore, compile with `-warnaserror`, publish the API, stage manifests as an artifact |
| **Test** | every PR and `main` | Both unit test projects in parallel, results and coverage published even on failure |
| **Package** | `main` only | Container build and push under an immutable tag, then an image scan |
| **Deploy** | `main`, after an environment approval | Apply manifests to AKS, wait for the rollout, smoke test, roll back on failure |

## Why it is ordered this way

- **Tests gate packaging; packaging gates deployment.** Nothing reaches a cluster that was not
  built from a green commit on the default branch.
- **A pull request builds and tests but produces no image.** An image nobody will deploy is
  registry cost and one more tag to misread during an incident.
- **The image tag is `$(Build.BuildId)-$(Build.SourceVersion)`, never `latest`.** "Which build is
  actually running?" is the first question in an incident, and a mutable tag makes it
  unanswerable.
- **Deployment is a `deployment` job against a named environment**, so the approvals configured on
  that environment gate the release — the same shape as the approval gate the application puts in
  front of a risky action.
- **The rollout is waited on.** A manifest being accepted is not the same as the new pods being
  healthy, and a stage that goes green on the former hides a failed deploy.
- **Secrets come from the cluster, never the image.** `appsettings.Development.json` carries a
  development-only signing key and a shared seed password. The Dockerfile deletes it at build time
  so the key cannot ship even if `ASPNETCORE_ENVIRONMENT` is set wrongly, and the Deploy stage has
  an explicit step for sourcing the real values from Key Vault.
- **The deployment runs one replica, and that is a defect rather than a choice** — the
  `IMemoryCache` data layer makes a second pod actively unsafe. See
  [iac/README.md](iac/README.md); it is the clearest concrete argument for the durable stores in
  [PRODUCTION_NOTES.md](../PRODUCTION_NOTES.md).
