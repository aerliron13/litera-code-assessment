using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Core.Approvals;

/// <inheritdoc cref="IApprovalService"/>
public sealed class ApprovalService : IApprovalService
{
    private readonly IApprovalStore _store;
    private readonly IAuditService _audit;
    private readonly IClock _clock;

    public ApprovalService(IApprovalStore store, IAuditService audit, IClock clock)
    {
        _store = store;
        _audit = audit;
        _clock = clock;
    }

    public async Task<ApprovalRecord> RecordApprovalAsync(
        string tenantId,
        string approverUserId,
        string approverRole,
        string action,
        string subjectId,
        string justification,
        CancellationToken cancellationToken = default)
    {
        Require(tenantId, nameof(tenantId));
        Require(approverUserId, nameof(approverUserId));
        Require(action, nameof(action));
        Require(subjectId, nameof(subjectId));

        if (!Roles.Satisfies(approverRole, Roles.Approver))
        {
            // Audit the refusal. A rejected attempt to grant an approval is exactly the kind of
            // event a compliance reviewer wants to see, so it must not fail silently.
            await _audit.WriteAsync(
                new AuditEvent
                {
                    TenantId = tenantId,
                    UserId = approverUserId,
                    Role = approverRole,
                    EventType = AuditEventTypes.ApprovalRejected,
                    Action = action,
                    SubjectId = subjectId,
                    Detail = $"Role '{approverRole}' may not record approvals.",
                    CorrelationId = Guid.NewGuid().ToString("n"),
                },
                cancellationToken)
                .ConfigureAwait(false);

            throw new InvalidWorkflowRequestException(
                $"Role '{approverRole}' may not record approvals; '{Roles.Approver}' is required.");
        }

        var record = new ApprovalRecord(
            Guid.NewGuid().ToString("n"),
            tenantId,
            action.Trim(),
            subjectId.Trim(),
            approverUserId.Trim(),
            string.IsNullOrWhiteSpace(justification) ? "(none supplied)" : justification.Trim(),
            _clock.UtcNow);

        _store.Append(record);

        await _audit.WriteAsync(
            new AuditEvent
            {
                TenantId = tenantId,
                UserId = approverUserId,
                Role = approverRole,
                EventType = AuditEventTypes.ApprovalRecorded,
                Action = record.Action,
                SubjectId = record.SubjectId,
                Detail = $"Approval {record.ApprovalId} recorded by '{record.ApprovedBy}'.",
                CorrelationId = record.ApprovalId,
            },
            cancellationToken)
            .ConfigureAwait(false);

        return record;
    }

    public Task<ApprovalDecision> VerifyApprovalAsync(
        string tenantId,
        string requestingUserId,
        string action,
        string subjectId,
        string? approvedBy,
        CancellationToken cancellationToken = default)
    {
        Require(tenantId, nameof(tenantId));
        Require(requestingUserId, nameof(requestingUserId));
        Require(action, nameof(action));
        Require(subjectId, nameof(subjectId));

        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(approvedBy))
        {
            return Denied(
                "No approver was referenced. A high-risk action requires an approval recorded by an "
                + "approver via POST /api/approvals.");
        }

        var approver = approvedBy.Trim();

        // Checked before the lookup, so that a genuine self-approval is refused for the right
        // reason rather than appearing to be a missing record.
        if (string.Equals(approver, requestingUserId.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return Denied(
                "Separation of duties: the user requesting the action may not be the user who "
                + "approved it.");
        }

        // The store read is tenant-scoped, so an approval recorded in another tenant is not merely
        // filtered out here — it is never a candidate.
        var record = _store.GetForTenant(tenantId).FirstOrDefault(candidate =>
            string.Equals(candidate.Action, action.Trim(), StringComparison.OrdinalIgnoreCase)
            && string.Equals(candidate.SubjectId, subjectId.Trim(), StringComparison.OrdinalIgnoreCase)
            && string.Equals(candidate.ApprovedBy, approver, StringComparison.OrdinalIgnoreCase));

        if (record is null)
        {
            return Denied(
                $"No approval record found for action '{action}' on subject '{subjectId}' approved by "
                + $"'{approver}' in this tenant.");
        }

        return Task.FromResult(ApprovalDecision.Approved(record));
    }

    public Task<IReadOnlyList<ApprovalRecord>> GetForTenantAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        Require(tenantId, nameof(tenantId));
        cancellationToken.ThrowIfCancellationRequested();

        var records = _store.GetForTenant(tenantId)
            .OrderBy(record => record.ApprovedAtUtc)
            .ToArray();

        return Task.FromResult<IReadOnlyList<ApprovalRecord>>(records);
    }

    private static Task<ApprovalDecision> Denied(string reason) =>
        Task.FromResult(ApprovalDecision.Denied(reason));

    private static void Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{parameterName} is required.", parameterName);
        }
    }
}
