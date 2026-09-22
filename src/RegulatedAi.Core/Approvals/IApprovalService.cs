using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Approvals;

/// <summary>
/// The exercise's <c>requestOrVerifyApproval</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The central design decision in this solution.</b> The brief's signature passes
/// <c>approvedBy</c> into the workflow, which invites the obvious implementation: if the field is
/// present, proceed. That would make the approval self-attested — the caller asking for the risky
/// action also supplies the evidence that it was approved, which is not an approval at all.
/// </para>
/// <para>
/// So <c>approvedBy</c> is treated as a <i>reference</i>. Approvals are recorded out of band by a
/// user holding the approver role (<see cref="RecordApprovalAsync"/>), and
/// <see cref="VerifyApprovalAsync"/> looks for a real record scoped to the tenant, the action and
/// the subject. Passing <c>approvedBy</c> with no matching record leaves the action blocked.
/// </para>
/// <para>
/// Separation of duties is enforced on top: the user requesting the action cannot be the user who
/// approved it, even when both are approvers and the record is genuine.
/// </para>
/// </remarks>
public interface IApprovalService
{
    /// <summary>
    /// Records a human approval. Writes an <c>approval.recorded</c> audit event as part of the
    /// same call, so an approval cannot be created without leaving a trace.
    /// </summary>
    /// <exception cref="InvalidWorkflowRequestException">
    /// The approver's role is insufficient, or the action or subject is missing. The HTTP layer
    /// also enforces the role; this is the defence in depth that survives a routing mistake.
    /// </exception>
    Task<ApprovalRecord> RecordApprovalAsync(
        string tenantId,
        string approverUserId,
        string approverRole,
        string action,
        string subjectId,
        string justification,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decides whether a recorded approval authorises this specific request. Fails closed: every
    /// path that is not an exact match returns a denial with a reason.
    /// </summary>
    Task<ApprovalDecision> VerifyApprovalAsync(
        string tenantId,
        string requestingUserId,
        string action,
        string subjectId,
        string? approvedBy,
        CancellationToken cancellationToken = default);

    /// <summary>Approvals recorded for a tenant. Used by the API for visibility during review.</summary>
    Task<IReadOnlyList<ApprovalRecord>> GetForTenantAsync(
        string tenantId,
        CancellationToken cancellationToken = default);
}
