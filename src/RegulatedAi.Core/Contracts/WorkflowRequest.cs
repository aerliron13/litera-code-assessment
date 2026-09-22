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
/// <see cref="SubjectId"/> is an explicit parameter rather than something extracted from
/// <see cref="Question"/>. Letting free text choose *what* to act on would hand target selection
/// to attacker-influenced content.
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
