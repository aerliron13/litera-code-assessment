namespace RegulatedAi.Core.Contracts;

/// <summary>
/// Everything an action handler is allowed to know. Notably it receives the *verified* approval
/// record, not the caller's claim to have one, and the risk level the gate actually computed.
/// </summary>
public sealed record ActionExecutionContext(
    string TenantId,
    string UserId,
    string Role,
    string Action,
    string SubjectId,
    RiskLevel RiskLevel,
    ApprovalRecord? Approval,
    string CorrelationId);

/// <summary>The result of attempting an action.</summary>
public sealed record ActionOutcome(ActionStatus Status, string Detail)
{
    public static ActionOutcome Executed(string detail) => new(ActionStatus.Executed, detail);

    public static ActionOutcome Unsupported(string action) => new(
        ActionStatus.UnsupportedAction,
        $"No handler is registered for action '{action}'.");

    public static ActionOutcome DeniedInsufficientRole(string role, string minimumRole) => new(
        ActionStatus.DeniedInsufficientRole,
        $"Role '{role}' is not permitted to execute this action; '{minimumRole}' or higher is required.");
}
