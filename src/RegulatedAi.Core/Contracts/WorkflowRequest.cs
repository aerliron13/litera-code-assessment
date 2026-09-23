namespace RegulatedAi.Core.Contracts;

/// <summary>
/// The internal orchestrator contract — the C# equivalent of the exercise's
/// <c>runWorkflow({ tenantId, userId, role, question, requestedAction, approvedBy })</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Trust boundary.</b> <see cref="TenantId"/>, <see cref="UserId"/> and <see cref="Role"/> are
/// populated *only* from validated JWT claims, in exactly one place
/// (<c>RegulatedAi.Api.Auth.ClaimsPrincipalExtensions.ToCaller</c>). No HTTP request body in this
/// solution has fields for them, so a caller cannot assert its own tenant or role.
/// </para>
/// <para>
/// <see cref="RequestedAction"/> and <see cref="SubjectId"/> are explicit parameters rather than
/// things extracted from <see cref="Question"/>.
/// </para>
/// <para>
/// <b>This is the design decision most worth arguing about, because the inference is easy.</b>
/// "Can we approve Vendor X to process customer payment data?" plainly implies
/// <c>markVendorApproved</c> on <c>vendor-x</c>, and a language model would resolve both from that
/// sentence reliably. Requiring the caller to state them looks like make-work.
/// </para>
/// <para>
/// The reason not to is an asymmetry in what the two inferences cost when wrong. A wrong risk
/// assessment produces a wrong recommendation, which a human reads before anything happens. A
/// wrong intent resolution <i>executes the wrong operation, or executes it against the wrong
/// subject</i> — and it does so having passed every gate, because the gates faithfully protect
/// whatever action they were handed. Approval, role and audit all describe the resolved action, so
/// resolving it wrongly corrupts the record of what was authorised rather than tripping a control.
/// </para>
/// <para>
/// Free text is also the one input an attacker most easily influences. Today it affects only
/// relevance ordering within a tenant's own corpus; if it selected the action and its target, a
/// crafted question — or retrieved evidence sharing a prompt with it — would be choosing what this
/// service does.
/// </para>
/// <para>
/// None of which means intent resolution should never be built. PRODUCTION_NOTES.md sets out how
/// to add it safely: a model <i>proposes</i> a structured intent, the proposal is validated against
/// the closed set of registered actions and the tenant's real subjects, ambiguity asks rather than
/// guesses, and the gates downstream stay exactly as they are.
/// </para>
/// <para>
/// <see cref="ApprovedBy"/> is a *reference* to a recorded approval, never an authorization in
/// itself — see <c>IApprovalService.VerifyApprovalAsync</c>.
/// </para>
/// </remarks>
public sealed record WorkflowRequest(
    string TenantId,
    string UserId,
    string Role,
    string Question,
    string? RequestedAction,
    string SubjectId,
    string? ApprovedBy,
    string CorrelationId);
