using RegulatedAi.Core.Contracts.Json;

namespace RegulatedAi.Core.Contracts;

/// <summary>
/// What the caller of the workflow already knows to be true, used to check the response against
/// reality rather than only against itself.
/// </summary>
/// <param name="RetrievedDocumentIds">
/// The documents tenant-scoped retrieval actually returned. Any citation outside this set is
/// either fabricated or belongs to another tenant; both are contract violations.
/// </param>
/// <param name="ApprovalVerified">Whether a real approval record was verified this run.</param>
public sealed record WorkflowValidationContext(
    string TenantId,
    string? RequestedAction,
    IReadOnlySet<string> RetrievedDocumentIds,
    IReadOnlySet<string> QuarantinedDocumentIds,
    bool ApprovalVerified);

/// <summary>
/// Enforces the invariants of <see cref="WorkflowResult"/> before it leaves the process.
/// </summary>
/// <remarks>
/// This is a backstop, not the primary control — the gates upstream are. It exists because the
/// cost of a wrong answer here is regulatory, so it is worth asserting the conclusions of those
/// gates a second time, cheaply, at the boundary. Each invariant below corresponds to a failure
/// that a future refactor could plausibly introduce.
/// </remarks>
public static class WorkflowResultValidator
{
    /// <summary>Returns every invariant breach found. Empty means the result is safe to return.</summary>
    public static IReadOnlyList<string> Inspect(WorkflowResult result, WorkflowValidationContext context)
    {
        var violations = new List<string>();

        if (!Enum.IsDefined(result.RiskLevel))
        {
            violations.Add($"riskLevel '{result.RiskLevel}' is not a defined risk band.");
        }

        if (!Enum.IsDefined(result.ActionStatus))
        {
            violations.Add($"actionStatus '{result.ActionStatus}' is not a defined action status.");
        }
        else if (!ActionStatusJsonConverter.AllowedWireValues.Contains(
                     ActionStatusJsonConverter.ToWireValue(result.ActionStatus)))
        {
            violations.Add($"actionStatus '{result.ActionStatus}' has no permitted wire representation.");
        }

        if (string.IsNullOrWhiteSpace(result.Recommendation))
        {
            violations.Add("recommendation must not be empty; a response with no recommendation is not actionable.");
        }

        if (string.IsNullOrWhiteSpace(result.CorrelationId))
        {
            violations.Add("correlationId must not be empty; a response must be traceable to its audit events.");
        }

        // A high-risk outcome that does not demand approval would defeat the entire gate.
        if (result.RiskLevel == RiskLevel.High && !result.RequiresApproval)
        {
            violations.Add("riskLevel 'high' must set requiresApproval to true.");
        }

        // Execution is only ever reachable through a verified approval when approval was required.
        if (result.ActionStatus == ActionStatus.Executed && result.RequiresApproval && !context.ApprovalVerified)
        {
            violations.Add("actionStatus 'executed' with requiresApproval true requires a verified approval record.");
        }

        if (result.ActionStatus == ActionStatus.Executed && string.IsNullOrWhiteSpace(context.RequestedAction))
        {
            violations.Add("actionStatus 'executed' is impossible when no action was requested.");
        }

        if (result.ActionStatus == ActionStatus.NotRequested && !string.IsNullOrWhiteSpace(context.RequestedAction))
        {
            violations.Add("actionStatus 'not_requested' contradicts a requested action.");
        }

        foreach (var citation in result.Citations)
        {
            if (string.IsNullOrWhiteSpace(citation.DocumentId) || string.IsNullOrWhiteSpace(citation.Snippet))
            {
                violations.Add("every citation must carry both a documentId and a snippet.");
                continue;
            }

            // The tenant-isolation backstop. Retrieval is already tenant-scoped; this catches the
            // case where some later change lets a document in by another route.
            if (!context.RetrievedDocumentIds.Contains(citation.DocumentId))
            {
                violations.Add(
                    $"citation '{citation.DocumentId}' was not returned by tenant-scoped retrieval for tenant " +
                    $"'{context.TenantId}'.");
            }

            // Quarantined content must never be presented as supporting evidence.
            if (context.QuarantinedDocumentIds.Contains(citation.DocumentId))
            {
                violations.Add($"citation '{citation.DocumentId}' is quarantined and must not be cited.");
            }
        }

        foreach (var quarantined in result.QuarantinedEvidence)
        {
            if (quarantined.MatchedPatterns.Count == 0)
            {
                violations.Add($"quarantined document '{quarantined.DocumentId}' must record why it was rejected.");
            }
        }

        if (result.Reasons.Any(string.IsNullOrWhiteSpace))
        {
            violations.Add("reasons must not contain empty entries.");
        }

        if (result.MissingEvidence.Any(string.IsNullOrWhiteSpace))
        {
            violations.Add("missingEvidence must not contain empty entries.");
        }

        return violations;
    }

    /// <summary>Throws <see cref="WorkflowContractViolationException"/> if any invariant is broken.</summary>
    public static void Validate(WorkflowResult result, WorkflowValidationContext context)
    {
        var violations = Inspect(result, context);
        if (violations.Count > 0)
        {
            throw new WorkflowContractViolationException(violations);
        }
    }
}
