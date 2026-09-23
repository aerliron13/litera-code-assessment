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

## Natural-language intent resolution

**Now.** `requestedAction` and `subjectId` are required fields. The caller states that it wants
`markVendorApproved` on `vendor-x`; the engine never infers either from `question`.

This is the weakest-looking decision in the solution and the one I most expect to be challenged,
because the inference is trivial. *"Can we approve Vendor X to process customer payment data?"*
names the action and the target unambiguously, a model would resolve both reliably, and making a
user restate them in structured fields is exactly the friction a natural-language interface exists
to remove. A real product does this.

**Why it is not done here.** Two inferences look similar and are not. Getting the *risk* wrong
produces a wrong recommendation, and a human reads it before anything happens — the output is
advice. Getting the *intent* wrong performs the wrong operation, or the right operation against the
wrong subject, and it does so having satisfied every control, because the gates faithfully protect
whatever action they were handed. The approval record, the role check and the audit entry all
describe the *resolved* action, so a bad resolution does not trip a control — it corrupts the record
of what was authorised. "Dave approved marking vendor-x compliant" is only true if `vendor-x` was
what the question meant.

It also matters that `question` is the input an attacker most easily influences. Today it affects
relevance ordering within the tenant's own corpus and nothing else. Promote it to choosing the
action and its target and a crafted question — or retrieved evidence that shares a prompt with it —
is deciding what the service does.

**How I would build it.** The shape that keeps the property is to let the model *propose* and make
the proposal earn its way through the same boundary as everything else:

- **Constrain the output, then validate it independently.** The model returns
  `{ action, subjectId, confidence }`. `action` must be one of `IActionService.RegisteredActions`;
  `subjectId` must resolve to a subject that exists in the caller's tenant. Anything else is a
  refusal, not a best guess. `PolicyRules.ForAction` already fails closed on an unrecognised action
  name, and `ActionService` already returns `unsupported_action` — so an invented action name
  cannot become a bypass, only a refusal.
- **Resolve intent from the question alone.** The intent prompt must not contain retrieved
  evidence. If it does, a poisoned document can rewrite the action, which is the whole attack this
  design exists to prevent. Retrieval happens *after* intent is fixed, never before.
- **Ambiguity asks; it does not pick.** More than one plausible action or subject, or confidence
  below threshold, returns a clarification rather than a choice. Fail closed here means fail
  *silent* — do nothing and ask.
- **Confirm before anything gated.** Echo the resolved intent back — "you are asking me to mark
  vendor-x approved" — and require confirmation for any action that needs approval. The human who
  approves must be approving a specific, stated action, not a sentence.
- **Bind the approval to the resolved pair.** An approval is already scoped to
  `(tenant, action, subject)`. It must be matched against what was *resolved*, so an approval
  obtained for `vendor-x` cannot authorise an execution the model later resolves to `vendor-y`.
- **Audit the inference as a first-class event.** A new event type recording the question, the
  proposed action and subject, the confidence, and the model and prompt version. "Why did it do
  that, to that vendor?" has to be answerable a year later, and the resolution step is where that
  answer lives.
- **Bound proposals by role.** The model may only propose actions the caller's role could execute,
  so intent resolution cannot widen authority even before the role gate sees it.

The interface to build it against already exists: `WorkflowRequest` takes `RequestedAction` and
`SubjectId` as data, so the resolver is a layer *above* the orchestrator that fills them in. Nothing
in the engine changes.

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
