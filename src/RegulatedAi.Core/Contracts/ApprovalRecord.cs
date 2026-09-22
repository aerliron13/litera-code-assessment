namespace RegulatedAi.Core.Contracts;

/// <summary>
/// A recorded human approval. This record — not a field on an incoming request — is what
/// authorizes a high-risk action. It is scoped to a tenant, an action name and a subject, so an
/// approval for one vendor cannot unlock another, and an approval in one tenant cannot unlock
/// anything in a second.
/// </summary>
public sealed record ApprovalRecord(
    string ApprovalId,
    string TenantId,
    string Action,
    string SubjectId,
    string ApprovedBy,
    string Justification,
    DateTimeOffset ApprovedAtUtc);

/// <summary>
/// The verdict from verifying an approval. <see cref="Reason"/> is written to be safe to return
/// to the caller and to read in an audit trail.
/// </summary>
public sealed record ApprovalDecision(bool IsApproved, string Reason, ApprovalRecord? Record)
{
    public static ApprovalDecision Denied(string reason) => new(false, reason, null);

    public static ApprovalDecision Approved(ApprovalRecord record) =>
        new(true, $"Approval {record.ApprovalId} verified.", record);
}
