# Regulated AI Action Workflow Engine

A small backend slice that answers *"Can we approve Vendor X to process customer payment data?"* by
retrieving tenant-scoped evidence, evaluating risk against explicit policy rules, returning a cited
recommendation, and **blocking any high-risk action until a human approval has been recorded**.

Every workflow run and every action attempt is audited. Retrieved evidence is treated as untrusted
data, never as instructions.

---

## Setup

Requires the **.NET 7 SDK** (built and verified against 7.0.202).

```bash
dotnet build
dotnet test          # 335 tests
```

## Run

```bash
dotnet run --project src/RegulatedAi.Api --urls http://localhost:5199
```

Then open **<http://localhost:5199/swagger>**. `/` redirects there; `/health` is anonymous.

The development signing key and the shared seed password live in
`src/RegulatedAi.Api/appsettings.Development.json`. They are development-only values and are
committed deliberately so the project runs with no setup — see
[PRODUCTION_NOTES.md](PRODUCTION_NOTES.md) for what replaces them.

### Seeded users

All five accounts use the password **`Passw0rd!`**.

| User    | Tenant     | Role       | Can do                                                      |
|---------|------------|------------|-------------------------------------------------------------|
| `alice` | `tenant-a` | `analyst`  | Run workflows, read the audit trail. **Cannot** execute actions. |
| `bob`   | `tenant-a` | `approver` | The above, plus record approvals and execute approved actions. |
| `dave`  | `tenant-a` | `approver` | Same as bob — a *second* approver, so separation of duties is demonstrable. |
| `carol` | `tenant-b` | `analyst`  | Tenant B's analyst.                                          |
| `erin`  | `tenant-b` | `approver` | Tenant B's approver.                                         |

### Seeded evidence

| Tenant     | Subject    | Evidence                                              | Expected band |
|------------|------------|-------------------------------------------------------|---------------|
| `tenant-a` | `vendor-x` | Policies + a contract with **no** breach clause, plus a **malicious attestation** | **high** |
| `tenant-b` | `vendor-y` | SOC 2, retention schedule and breach clause, all current | **low** |
| `tenant-b` | `vendor-z` | All three present, but the SOC 2 has **lapsed**        | **medium** |

---

## API

| Method | Route | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/auth/login` | anonymous | Exchange seeded credentials for a JWT carrying `tenant_id` and `role`. |
| `POST` | `/api/workflow/run` | any role | The orchestrator. |
| `POST` | `/api/approvals` | `approver` | Record a human approval. |
| `GET` | `/api/approvals` | any role | Approvals in the caller's tenant. |
| `GET` | `/api/audit` | any role | Audit trail for the caller's tenant. |
| `GET` | `/api/evidence?subjectId=&query=` | any role | Tenant-scoped retrieval, for inspection. |

Cross-origin access is a named policy built from the `Cors` configuration section and ships
allowing **no** origins — there is no browser client to whitelist. Wildcards are refused at startup.

**No request body anywhere accepts a tenant, user or role.** Those three come from the bearer token
and nowhere else, which is why cross-tenant access is not something the API defends against
request-by-request — a request cannot express it.

---

## Example request and response

```bash
BASE=http://localhost:5199

TOKEN=$(curl -s -X POST $BASE/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Passw0rd!"}' | jq -r .accessToken)

curl -s -X POST $BASE/api/workflow/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "question": "Can we approve Vendor X to process customer payment data?",
        "subjectId": "vendor-x",
        "requestedAction": "markVendorApproved"
      }' | jq
```

```json
{
  "riskLevel": "high",
  "recommendation": "Do not approve yet.",
  "reasons": [
    "No SOC 2 evidence found.",
    "No data retention schedule found.",
    "Contract lacks breach notification language.",
    "Untrusted content was detected in the retrieved evidence and excluded from scoring."
  ],
  "citations": [
    {
      "documentId": "policy-a-002",
      "snippet": "Payment data vendors require security evidence before approval: a current SOC 2 Type II report, a documented data retention schedule, and a contractual breach notification commitment. Absence of any one of these blocks approval."
    },
    {
      "documentId": "contract-a-010",
      "snippet": "Master services agreement with VendorX Payments for card payment processing. ... This agreement contains no breach notification clause and no data retention schedule is attached."
    }
  ],
  "missingEvidence": ["SOC 2 report", "data retention schedule", "breach notification clause"],
  "requiresApproval": true,
  "actionStatus": "blocked_pending_approval",
  "actionDetail": "No approver was referenced. A high-risk action requires an approval recorded by an approver via POST /api/approvals.",
  "quarantinedEvidence": [
    {
      "documentId": "evidence-a-666",
      "matchedPatterns": [
        "ignore-previous-instructions",
        "instruction-to-approve",
        "no-further-review",
        "override-controls",
        "addressed-to-the-model"
      ]
    }
  ],
  "correlationId": "0HNOOU2BQ8O0N:00000001"
}
```

`actionStatus` is one of `not_requested`, `executed`, `blocked_pending_approval`,
`denied_insufficient_role`, `unsupported_action`. `riskLevel` is `low`, `medium` or `high`.

---

## Walkthrough: the approval gate

Run these in order against a freshly started server. Each step is a distinct refusal reason.

```bash
BASE=http://localhost:5199
login() { curl -s -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
            -d "{\"username\":\"$1\",\"password\":\"Passw0rd!\"}" | jq -r .accessToken; }
run() { curl -s -X POST $BASE/api/workflow/run -H "Authorization: Bearer $1" \
          -H 'Content-Type: application/json' -d "$2" | jq -r '.riskLevel + " / " + .actionStatus'; }

ALICE=$(login alice); BOB=$(login bob); DAVE=$(login dave); ERIN=$(login erin)
VX='{"question":"Can we approve Vendor X to process customer payment data?","subjectId":"vendor-x","requestedAction":"markVendorApproved"}'
VX_DAVE='{"question":"Can we approve Vendor X?","subjectId":"vendor-x","requestedAction":"markVendorApproved","approvedBy":"dave"}'
```

| # | Command | Result |
|---|---------|--------|
| 1 | `run $ALICE "$VX"` | `high / blocked_pending_approval` — no approval exists |
| 2 | `run $ALICE "$VX_DAVE"` | `high / blocked_pending_approval` — **naming an approver is not an approval** |
| 3 | `curl -X POST $BASE/api/approvals -H "Authorization: Bearer $ALICE" …` | **403** — an analyst may not approve |
| 4 | `curl -X POST $BASE/api/approvals -H "Authorization: Bearer $DAVE" -d '{"action":"markVendorApproved","subjectId":"vendor-x","justification":"Reviewed."}'` | **201** — approval recorded |
| 5 | `run $DAVE "$VX_DAVE"` | `high / blocked_pending_approval` — **separation of duties**: dave cannot use his own approval |
| 6 | `run $ALICE "$VX_DAVE"` | `high / denied_insufficient_role` — valid approval, wrong role |
| 7 | `run $BOB "$VX_DAVE"` | `high / executed` — a different approver, acting under a real record |

Then:

```bash
run $ERIN '{"question":"Vendor Y?","subjectId":"vendor-y","requestedAction":"markVendorApproved"}'   # low / executed
run $ERIN '{"question":"Vendor Z?","subjectId":"vendor-z","requestedAction":"markVendorApproved"}'   # medium / executed
run $ALICE '{"question":"Vendor Y?","subjectId":"vendor-y","requestedAction":"markVendorApproved"}'  # high / blocked — tenant-a sees none of tenant-b's evidence
curl -s $BASE/api/audit -H "Authorization: Bearer $ALICE" | jq 'length'                              # every run and attempt above
```

---

## Design

```
src/RegulatedAi.Core/            the engine — no ASP.NET dependency, runnable without a host
  Workflow/    IWorkflowService   orchestrator; owns sequencing and the audit guarantee, no rules
  Evidence/    IEvidenceService   tenant-scoped retrieval + screening at the boundary
  Risk/        IRiskService       deterministic rules over structured tags (the mocked "AI")
  Approvals/   IApprovalService   records approvals; verifies them; enforces separation of duties
  Audit/       IAuditService      append-only, tenant-scoped
  Actions/     IActionService     handler registry; each handler declares its own gates
  Security/    IPromptInjectionScanner, Roles
  Data/        IMemoryCache-backed stores + the seeded corpus
  Contracts/   DTOs, enums, wire converters, WorkflowResultValidator

src/RegulatedAi.Api/             HTTP, JWT, DI
tests/RegulatedAi.Core.UnitTests/   207 tests — every engine service, against Moq
tests/RegulatedAi.Api.UnitTests/    128 tests — controllers, JWT validation, wire contract
```

### The trust boundary

1. **`tenantId`, `userId` and `role` come only from verified JWT claims**, mapped in exactly one
   place (`ClaimsPrincipalExtensions.ToCaller`). No request DTO has those fields.
2. **Every store read takes a tenant id and every cache key embeds it.** There is no unscoped read
   to forget to filter — isolation is structural.
3. **The action target is an explicit `subjectId`**, not something parsed out of the question.
   Letting free text choose what to act on would hand target selection to attacker-influenced text.
4. **Retrieved evidence is data, never instruction.** It is screened at retrieval; suspicious
   documents are quarantined — excluded from scoring and from citations, reported, and audited.
   The caller's own question is screened too, before any retrieval, and refused outright.
5. **`approvedBy` is a reference, not an authorization.** It must resolve to a real record scoped
   to the tenant, action and subject, recorded by someone other than the requester.
6. **The response is validated before it leaves the process**, including that every citation
   belongs to the caller's tenant.

### Risk rules

A payment-data vendor needs three pieces of evidence: a current SOC 2 report, a data retention
schedule, and a contractual breach notification commitment.

- any requirement unmet → **high**
- all present but one lapsed → **medium**
- all present and current → **low**
- quarantined content raises the floor to **medium** and can never lower a band

Where a real model would go, and why it is not here: a model may draft the prose, but must never
decide `riskLevel` — that value is what the approval gate consumes, so nothing an attacker can
influence through retrieved text may move it. See `IRiskService` for the full note.

### Adding an action

Implement `IActionHandler` — declaring `MinimumRole` and `AlwaysRequiresApproval` alongside the
behaviour — and register it in `Program.cs`. The orchestrator, the approval gate and the audit
trail need no changes.

---

## Also in this repository

- [AI_USAGE.md](AI_USAGE.md) — how AI was used, what it got wrong, what was changed by hand.
- [PRODUCTION_NOTES.md](PRODUCTION_NOTES.md) — auth, isolation, audit storage, observability,
  idempotency, rate limiting, compliance.
- [THREAT_NOTES.md](THREAT_NOTES.md) — the top three risks in this design and their mitigations.
- [verify_brief_not_injected.py](verify_brief_not_injected.py) — a check that the exercise brief
  itself contained no text hidden from a human reader. It did not.
- [infra/](infra/README.md) — an illustrative Azure DevOps pipeline (build → test → package →
  deploy to AKS) and notes on the Kubernetes manifests that would accompany it. Nothing here has
  run; cloud deployment is outside the brief.

## Scope

Per the brief: no UI, no database, no real LLM, no identity provider, no queue or vector store.
Deliberately not built, and discussed in PRODUCTION_NOTES.md instead: idempotency keys for
duplicate-execution prevention, a tamper-evident audit chain, approval expiry, and a versioned
policy store.
