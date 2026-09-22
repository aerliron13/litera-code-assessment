using Microsoft.Extensions.Logging;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Core.Actions.Handlers;

/// <summary>
/// The one risky action: marking a vendor approved to process payment data.
/// </summary>
/// <remarks>
/// <para>
/// Mocked, as the brief requires — it performs no outbound call and changes nothing irreversible.
/// The <c>action.executed</c> audit event is the record that it happened; there is deliberately no
/// second "vendor approved" store, because an audit trail that is the source of truth for what was
/// done is better than one that can disagree with a side table.
/// </para>
/// <para>
/// <see cref="AlwaysRequiresApproval"/> is false: approval is demanded whenever the assessment
/// comes back high risk, which for a payment-data vendor with any evidence gap it always does. A
/// deployment that wanted a human in the loop for *every* vendor approval regardless of evidence
/// would flip this to true and nothing else would change.
/// </para>
/// </remarks>
public sealed class MarkVendorApprovedHandler : IActionHandler
{
    private readonly ILogger<MarkVendorApprovedHandler> _logger;

    public MarkVendorApprovedHandler(ILogger<MarkVendorApprovedHandler> logger) => _logger = logger;

    public string ActionName => ActionNames.MarkVendorApproved;

    public string MinimumRole => Roles.Approver;

    public bool AlwaysRequiresApproval => false;

    public Task<ActionOutcome> ExecuteAsync(
        ActionExecutionContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _logger.LogInformation(
            "Mock action {Action} applied to {SubjectId} for tenant {TenantId} by {UserId} "
            + "under approval {ApprovalId}",
            ActionName,
            context.SubjectId,
            context.TenantId,
            context.UserId,
            context.Approval?.ApprovalId ?? "(none required)");

        var basis = context.Approval is null
            ? $"risk assessed as {context.RiskLevel.ToString().ToLowerInvariant()}, no approval required"
            : $"approval {context.Approval.ApprovalId} recorded by '{context.Approval.ApprovedBy}'";

        return Task.FromResult(ActionOutcome.Executed(
            $"Vendor '{context.SubjectId}' marked approved for tenant '{context.TenantId}' ({basis})."));
    }
}
