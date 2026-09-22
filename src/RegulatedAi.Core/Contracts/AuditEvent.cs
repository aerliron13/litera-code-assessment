namespace RegulatedAi.Core.Contracts;

/// <summary>
/// An append-only audit record. <see cref="EventId"/> and <see cref="OccurredAtUtc"/> are stamped
/// by <c>AuditService</c> and overwrite whatever a caller supplied, so a caller cannot forge the
/// identity or timing of an event.
/// </summary>
/// <remarks>
/// <b>Safe logging.</b> <see cref="Detail"/> and <see cref="Reasons"/> hold document identifiers,
/// rule names and pattern names — never retrieved document text, never a token, never a
/// credential. Audit records get read by people during incidents and shipped to log sinks; they
/// are the wrong place to replay attacker-controlled prose.
/// </remarks>
public sealed record AuditEvent
{
    public string EventId { get; init; } = string.Empty;

    public DateTimeOffset OccurredAtUtc { get; init; }

    public required string TenantId { get; init; }

    public required string UserId { get; init; }

    public required string Role { get; init; }

    /// <summary>One of <see cref="AuditEventTypes"/>.</summary>
    public required string EventType { get; init; }

    public string? Action { get; init; }

    public string? SubjectId { get; init; }

    public RiskLevel? RiskLevel { get; init; }

    public ActionStatus? ActionStatus { get; init; }

    public string? Detail { get; init; }

    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();

    public required string CorrelationId { get; init; }
}

/// <summary>
/// The closed set of audit event types. Distinct types (rather than one generic "attempt" type
/// with a status field) exist so that an operator can alert directly on, say,
/// <see cref="ActionBlockedPendingApproval"/> without parsing payloads.
/// </summary>
public static class AuditEventTypes
{
    public const string WorkflowRun = "workflow.run";
    public const string WorkflowRejected = "workflow.rejected";

    /// <summary>The caller's own question contained instruction-like content and was refused.</summary>
    public const string RequestInjectionRejected = "request.injection_rejected";

    public const string EvidenceQuarantined = "evidence.quarantined";
    public const string ApprovalRecorded = "approval.recorded";
    public const string ApprovalRejected = "approval.rejected";
    public const string ActionExecuted = "action.executed";
    public const string ActionBlockedPendingApproval = "action.blocked_pending_approval";
    public const string ActionDeniedInsufficientRole = "action.denied_insufficient_role";
    public const string ActionUnsupported = "action.unsupported";
    public const string OutputValidationFailed = "output.validation_failed";

    /// <summary>Prefix shared by every action-attempt event type.</summary>
    public const string ActionPrefix = "action.";

    /// <summary>Maps an attempt outcome to its audit event type. Exhaustive by design.</summary>
    public static string ForActionStatus(ActionStatus status) => status switch
    {
        Contracts.ActionStatus.Executed => ActionExecuted,
        Contracts.ActionStatus.BlockedPendingApproval => ActionBlockedPendingApproval,
        Contracts.ActionStatus.DeniedInsufficientRole => ActionDeniedInsufficientRole,
        Contracts.ActionStatus.UnsupportedAction => ActionUnsupported,
        Contracts.ActionStatus.NotRequested => throw new ArgumentOutOfRangeException(
            nameof(status), status, "No action was attempted, so no action event should be written."),
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unmapped action status."),
    };
}
