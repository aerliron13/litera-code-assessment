# AI Usage

## Tools

- **Claude Code** (Claude Opus), agentic CLI session, for the whole build: reading the brief,
  scaffolding the solution, writing the services, the tests and these documents.
- **`pdftotext`** (poppler) to extract the brief from PDF, plus a short Python script to inspect
  the PDF's content streams — see *Checking the brief itself* below.
- No AI in the running product. The risk engine is deterministic C#; `IRiskService` documents
  where a model would go and why it deliberately does not decide `riskLevel`.

## How I worked

I set the architecture up front and then drove the session in small, specific corrections rather
than accepting a generated solution. The opening instruction fixed the shape — REST API in C#, a
login endpoint returning a JWT with a tenant claim, an `IWorkflowService` for `RunWorkflow`, plus
`IEvidenceService` / `IRiskService` / `IApprovalService` / `IAuditService` / `IActionService`,
`IMemoryCache` for the data layer, and full DI in `Program.cs` — and everything after that was
review and redirection.

### Prompts that earned their keep

Short, specific and corrective beat long and descriptive every time.

| Prompt | Why it mattered |
|---|---|
| *"let's also add a tenantID check as well"* | The generated code read the tenant claim but never validated it. A tenant id is a storage key — an unknown value silently addresses an empty partition, which reads as "no evidence found", which is a plausible-looking high-risk answer about a tenant that does not exist. Now checked at issuance, at authentication and at claims mapping. |
| *"let's make this app setting values instead of hard-coded"* | Key length, token lifetime and its bounds had been baked into `JwtOptions.Validate`. They are policy, so they belong in configuration. I kept one hard floor — configuration can raise the 256-bit HS256 minimum but not go under it. |
| *"let's have a BaseRegulatedAiTenantController that inherits from ControllerBase"* | Each controller was reading claims for itself. A base class makes `[Authorize]` and the claims mapping the default rather than something four files each have to remember. |
| *"add the authorize attribute to both workflow and approval"* | Inheriting `[Authorize]` from the base works, but a reader of the file cannot see it. Redundant by design. |
| *"these tests aren't needed, this was just done to avoid having to set up a db"* | It had written a test class for the `IMemoryCache` store plumbing. That is scaffolding to avoid standing up a database, not the deliverable. Deleted. |
| *"we are using the seed data for unit tests, let's use Moqs instead"* | Unit tests had been wired to the real seeded corpus, which couples every rule to a demo fixture — a seeded document changes and unrelated tests break, or a rule passes for reasons unconnected to the rule. Rewritten onto Moq with per-test data. |
| *"even the API can be moqed unit tests, there is no real need for integration tests since we aren't integrating with anything"* | Correct, and it cut a `WebApplicationFactory` project. It also created a real blind spot — see the DI bug below. |
| *"the promptinjectionscanner should be called from the workflow service before we make it to the evidence service"* | The scanner only screened retrieved documents. The caller's own question is attacker-controlled too, and it steers retrieval ordering. Now screened first and refused with a 400. |
| *"I also want to test if we change the contents of the JWT after login, subsequent requests fail"* | Produced `JwtTamperingTests`, and forced the token-validation configuration out of `Program.cs` so it could be tested — which then exposed the static-state problem below. The single most productive prompt of the session. |
| *"were there any AI gotchas in the original document"* | See below. |
| *"lets add CORS as well even though we have nothing to whitelist, make it a configuration setting"* | Deny-by-default policy present and explicit, so enabling a front end is a deliberate configuration change rather than a decision made by whoever is debugging a CORS error. |

## What the AI got wrong

All of these are real and were caught in this session. Two of them only surfaced because I insisted
on running the thing.

1. **A missing DI registration — invisible to every test.** `ITokenService` was never registered in
   `Program.cs`. Every test passed; the app returned 500 on login. Mocked controller tests
   *structurally cannot* catch this, because they inject the dependency themselves. This is the
   direct cost of dropping the integration project, and I accept the trade — but it is why I ran the
   full scenario by hand rather than trusting a green suite.

2. **`System.Text.Json` converter precedence, backwards.** It assumed a `[JsonConverter]` attribute
   on an enum takes precedence over a converter in `JsonSerializerOptions.Converters`. It is the
   reverse. A global `JsonStringEnumConverter(camelCase)` silently overrode the per-enum converters
   and shipped `actionStatus: "blockedPendingApproval"` where the brief specifies
   `blocked_pending_approval`. Nothing threw. Found by reading the actual HTTP response. Fixed by
   removing the global converter entirely and giving each enum its own — and by adding
   `WireContractTests`, which assert the serialized string rather than the enum value.

3. **Correctness that depended on a mutated static.** Claim names only came through as `sub` /
   `role` because `Program.cs` cleared `JwtSecurityTokenHandler.DefaultInboundClaimTypeMap` at
   startup. It worked in the app and broke the moment a test built a handler of its own. That is a
   genuine design smell, not a test problem: correct behaviour hinging on process-global state one
   composition root happened to mutate. Replaced with instance-level configuration in
   `JwtBearerConfiguration.CreateTokenHandler()`.

4. **A verification that passed for the wrong reason.** My first tampered-JWT check ran a Python
   snippet reading `/tmp/a.tok`. Git Bash and Windows Python resolve `/tmp` differently, so the file
   was not found, the token variable was empty — and the request returned **401**, exactly the
   result I was hoping for. It proved nothing. Redone passing the token as an argument, with the
   decoded claims and token lengths printed so the check is visibly testing what it claims to.
   A green result from a broken harness is worse than a red one.

5. **An over-specific exception assertion.** The tamper tests asserted
   `SecurityTokenInvalidSignatureException`; the library raises
   `SecurityTokenSignatureKeyNotFoundException` for a tampered HS256 payload with no `kid`, and
   xUnit's `Assert.Throws<T>` is exact-type. Relaxed to the common base, since the property that
   matters is that no `ClaimsPrincipal` is produced.

6. **Inconsistent normalisation.** `Tenants.IsKnown` trimmed its input; `Roles.IsKnown` did not, so
   a whitespace-padded role claim was rejected while a padded tenant claim was accepted. Caught by a
   test I had written expecting them to agree. Normalisation now lives in one place.

7. **Two malformed assertions** that compiled but tested nothing — a conditional expression built
   out of `StringComparison.OrdinalIgnoreCase.Equals("x","x")`, and an `Assert.Equal` whose
   expected and actual were the same expression. Both caught on review. Generated test code needs
   reading as carefully as generated production code; assertions that cannot fail are the easiest
   thing to miss.

## What I changed by hand or by direction

- The whole architecture: layering, the interface set, `IMemoryCache` for data, full DI in
  `Program.cs`.
- **The approval model** — the most important decision in the solution. The brief's own
  `runWorkflow({ …, approvedBy })` signature invites treating the field as the authorization, which
  makes the approval self-attested by the party requesting the risky action. I chose recorded
  approvals through a separate role-restricted endpoint, with `approvedBy` as a reference only, plus
  separation of duties. The AI offered the naive reading as a valid option; it is the one an
  interviewer would push on.
- Tenant-id validation at three layers; JWT policy numbers into configuration; the base tenant
  controller; explicit `[Authorize]`; inbound question screening; CORS as configuration.
- Test strategy: Moq throughout, no seeded corpus in unit tests, no integration project, no tests
  for the cache plumbing or for CORS.
- Removed the tests it wrote for the in-memory store plumbing.

## Checking the brief itself

The exercise is about treating retrieved content as untrusted. The brief arrived as a PDF, went
through a text extractor, and was then read as instructions — which makes it exactly the kind of
content the exercise is about. So I checked it before building anything, because "I only trust
documents from people I trust" is precisely the assumption prompt injection exploits.

`verify_brief_not_injected.py` looks for text a human reader cannot see but an extractor picks up —
white-on-white text being the classic trick. The brief is clean:

- No `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/Annots`, `/AA` or
  `/RichMedia`.
- 3 of 172 text-draw operations use a white fill, and all three are the evaluation table's header
  row (`Category`, `Points`, `What we are looking for`) on its dark blue band — visible to a reader.
- Smallest font size 8.04pt, so no micro-text.
- The only instruction-shaped phrases are the brief's own requirements about handling a malicious
  evidence snippet.

The script is kept in the repository deliberately. The habit is the point of the exercise, and it is
the same reasoning as `PromptInjectionScanner`: screen untrusted content where it enters, and record
what you found.

## Assessment

AI was a genuine accelerator for volume — 335 tests, four documents and the scaffolding are far more
than an hour of typing — and it was reliably wrong in a specific way: it produced code that *looked*
right and was internally consistent, including its own tests. The two defects that would have
shipped were both invisible to a green test suite and both found in the first minute of actually
running the service.

What I would keep doing: set the architecture first, correct in small specific increments, read the
generated tests as adversarially as the generated code, and run the thing.
