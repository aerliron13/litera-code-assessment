# Production Notes

How this slice becomes a real service. Each section names what is here now, what replaces it, and
why — in roughly the order I would actually do it.

---

## Authentication and identity

**Now.** The service signs its own HS256 tokens from a symmetric key in configuration, against five
seeded accounts sharing one plaintext password. The issuer and the verifier are the same process
holding the same secret.

**Then.**

- Delegate to an OIDC provider (Entra ID, Okta). The API becomes a resource server only: validate
  RS256/ES256 against the provider's published JWKS, cache the keys, honour rotation. Nothing in
  this service issues a token, and there is no shared secret to leak.
- `tenant_id` and `role` become provider-issued claims mapped from group or app-role assignments,
  so tenant membership is administered where the rest of the organisation's access is.
- Short access tokens (5–15 min) plus refresh, and a revocation path — today a stolen token is
  valid for its full 30 minutes with no way to kill it. `jti` is already stamped, so a denylist
  keyed on it is the cheap first step.
- Passwords, if any survive, become Argon2id — never the current comparison, which exists only
  because the brief rules out an identity provider.
- Keys from a managed secret store (Key Vault, Secrets Manager) with rotation, never appsettings.

**Already done and worth keeping:** algorithm pinning, zero clock skew, issuer and audience
validation, startup validation of key length, refusal to mint a token naming an unknown tenant or
role, and explicit instance-level claim-name mapping rather than a mutated static.

---

## Tenant isolation

**Now.** Structural in the application: identity comes only from verified claims, every store method
takes a tenant id, every cache key embeds it, and there is no unscoped read. The output validator
refuses to return a citation that tenant-scoped retrieval did not produce.

**Then.**

- Push the boundary below the application. Row-level security policies, or a schema per tenant, so
  the database refuses a cross-tenant read even when the application asks for one. Application-layer
  isolation is one forgotten `WHERE` clause from failing; the database is not.
- Tenant id on every log line, metric and trace span, so "did anything cross a boundary?" is a
  query rather than an audit.
- A reconciliation job asserting that no stored record's tenant disagrees with its partition.
- Keep the output validator. It is cheap, and it is the only control that catches a leak introduced
  by a future refactor rather than by today's code.

---

## Audit storage

**Now.** Append-only in `IMemoryCache`. Entries are written `NeverRemove` and appends are locked so
concurrent writes cannot lose a record, but the process losing its memory loses the trail.

**Then.**

- Durable append-only storage the application can write but not amend or delete — an immutability
  policy on blob storage, a WORM-configured bucket, or an append-only table with no UPDATE/DELETE
  grant for the application's role. The application having permission to rewrite its own audit trail
  defeats the purpose of having one.
- Tamper evidence: chain each event to the previous one's hash, or sign batches. Deliberately not
  built here — it would have been ceremony without the durable store underneath it.
- Retention aligned to the regulatory clock (often 7 years for vendor due diligence), with legal
  hold, and deletion that is itself audited.
- Ship to a SIEM. `action.blocked_pending_approval`, `action.denied_insufficient_role`,
  `evidence.quarantined`, `approval.rejected` and `output.validation_failed` are alertable events
  today — the event types are already distinct precisely so an operator can alert on one without
  parsing payloads.
- Write the audit event in the same transaction as the action it records. Right now an action could
  in principle succeed while its audit write fails; with a real store that becomes a genuine
  integrity gap, and the fix is transactional or an outbox.

---

## Observability

**Now.** Structured logs carrying tenant, user, role, action, subject, risk level, status and a
correlation id — and never evidence text, tokens or credentials. A `correlationId` is returned to
the caller and appears on every audit event for the run.

**Then.**

- OpenTelemetry traces spanning retrieve → assess → gate → execute, so "why was this blocked?" is
  answerable from a trace rather than reconstructed from logs.
- Metrics that mean something to this domain: decisions by risk band and tenant, block rate,
  approval latency (recorded → used), quarantine rate, and rule-version distribution. A sudden fall
  in the block rate is the signal that something has gone wrong with the gate.
- Alert on quarantine rate by tenant — a spike means someone is uploading poisoned evidence.
- Propagate a caller-supplied `traceparent` instead of relying on `HttpContext.TraceIdentifier`,
  which is per-process and not meaningful across services.
- Keep the safe-logging rule explicit in review: audit records get read by people during incidents.

---

## Idempotency and duplicate execution

This is the live follow-up question, and the honest answer is that **nothing here prevents duplicate
execution**. `markVendorApproved` is idempotent by luck — marking an already-approved vendor approved
again changes nothing — but the follow-up's `exportPrivilegedSummary` would not be: a retried
request would export privileged material twice, to two places, under one approval.

What I would build:

- **An `Idempotency-Key` header, required on any state-changing action.** Persist
  `(tenantId, idempotencyKey)` with the request hash and the stored response, in the same
  transaction as the action. A replay with the same key returns the stored response without
  re-executing; a replay with the same key but a *different* request body is a 409, because that is
  a client bug, not a retry.
- **Single-use approvals for non-idempotent actions.** Mark the `ApprovalRecord` consumed when it
  authorises an execution, atomically. One approval, one execution — which is what "a human approved
  this" should mean for an irreversible action.
- **A uniqueness constraint as the real guard.** Optimistic concurrency or a unique index on
  `(tenantId, action, subjectId, approvalId)`, so two concurrent requests race to the database and
  exactly one wins. An in-memory check cannot survive two instances.
- **Distinguish retryable from non-retryable.** Retry retrieval with jittered backoff; never retry
  an action automatically. A failed action whose outcome is unknown is a human's problem, recorded
  as such, not something to attempt again hopefully.
- Handlers declare whether they are idempotent, so the framework knows which ones need this.

---

## Rate limiting and resource protection

**Now.** Nothing. Every screening regex carries a match timeout, and a timeout is treated as
suspicious rather than clean, which is the one denial-of-service concern that is addressed.

**Then.** Per-tenant and per-user token-bucket limits (ASP.NET Core's built-in rate limiter is
enough) so one tenant cannot exhaust capacity; a separate, much tighter limit on login to blunt
credential stuffing; request size caps; a global cap on documents per retrieval and on evidence
corpus size per tenant; and timeouts plus circuit breakers on every downstream call once retrieval
stops being in-memory. If a model is introduced, per-tenant token budgets — cost is a resource too.

---

## Data layer

**Now.** `IMemoryCache` behind four interfaces, as the brief requires. A cache is not a store: it can
evict, it is per-process, and it disappears on restart. The interfaces exist so this is the only
thing that changes.

**Then.** A relational store for approvals, actions and audit — transactional, with row-level
security. Evidence metadata relational; document bodies in object storage; retrieval through a real
index (BM25 or a vector store) once the corpus is larger than a fixture. Note that adding a vector
store *widens* the injection surface, because embedding similarity is influenceable by document
content — which is an argument for keeping requirement satisfaction based on ingestion-assigned
tags rather than on retrieval relevance, as it is now.

---

## Policy and rules

**Now.** `PolicyRules` is a small C# class, as the brief asks for.

**Then.** Requirements become versioned data owned by compliance, not constants in a file. Critically,
every decision records **which version of the rules produced it** — otherwise a decision made last
year becomes inexplicable the moment the rules change, which is exactly the question an auditor
asks. Rule changes get their own review, approval and audit trail, and a dry-run mode to see what a
proposed change would have done to historical decisions.

---

## Cross-origin access

**Now.** A named policy built from configuration, allowing **no** origins by default; wildcards are
refused at startup, credentials disallowed, methods and headers restricted to what the API exposes.
There is no browser client, so nothing is whitelisted.

**Then.** List the real front-end origins per environment. The reason it is configuration rather
than code: a blocked browser request produces an opaque console error, and the quickest way to
silence it is `AllowAnyOrigin` — which, on an API whose bearer token lives in the browser, hands
every site the user visits the ability to call it. Making origins a config list means the fix is to
add one origin.

---

## Deployment and operations

Containerised, non-root, read-only filesystem. Health endpoints split into liveness and readiness —
`/health` today is liveness only and would need readiness once there are dependencies. Configuration
and secrets from the platform, never from committed appsettings; the current
`appsettings.Development.json` values are committed deliberately so the exercise runs, and would be
deleted on the first day of real work. Blue/green or canary, with the block rate and quarantine rate
as canary signals. Backups and a tested restore for the audit store, since it is the record you most
need after an incident and the one nobody notices is broken.

---

## Compliance and legal

- **Data residency.** Tenants in regulated markets will require their evidence to stay in-region;
  that is a deployment-topology decision (regional stacks, regional storage) and it is much cheaper
  to make before launch than after.
- **Retention and deletion.** Per-tenant schedules, documented, enforced by a job rather than by
  intention. Deletion requests (GDPR Art. 17) need to reach evidence, audit and backups, with a
  defensible answer for why audit records are retained where a legal basis requires it.
- **Evidence provenance.** Every document should carry who supplied it, when, and whether it was
  verified. A decision citing an unverified upload is a materially weaker decision, and today
  nothing records the difference.
- **Explainability.** The reasons and citations already make a decision defensible to a regulator.
  Keeping that property is the strongest argument against handing `riskLevel` to a model: "the
  model said so" is not an audit answer.
- **Human accountability.** An approval names a person. That is what makes it an approval — so
  approver identity must come from a real identity provider, and step-up authentication on approval
  is worth the friction.
- **DPIA and vendor assessment** for the service itself, plus records of processing. If a model is
  introduced, add model provenance and version to every decision record, and confirm the provider's
  terms on training and retention — sending tenant evidence to a third party is itself a
  sub-processor relationship that tenants must be told about.
