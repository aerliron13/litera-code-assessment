namespace RegulatedAi.Core.Contracts;

/// <summary>
/// The constrained response shape. Property declaration order is the JSON serialization order,
/// and deliberately matches the contract given in the exercise brief.
/// </summary>
/// <remarks>
/// Every instance passes <see cref="WorkflowResultValidator"/> before it leaves the process.
/// "Validate or clearly constrain the structured output shape" is treated here as a security
/// control, not a formatting nicety: the validator is also the last line of defence against a
/// citation from another tenant reaching the caller.
/// </remarks>
public sealed record WorkflowResult
{
    public required RiskLevel RiskLevel { get; init; }

    public required string Recommendation { get; init; }

    public required IReadOnlyList<string> Reasons { get; init; }

    public required IReadOnlyList<Citation> Citations { get; init; }

    public required IReadOnlyList<string> MissingEvidence { get; init; }

    public required bool RequiresApproval { get; init; }

    public required ActionStatus ActionStatus { get; init; }

    /// <summary>Human-readable explanation of <see cref="ActionStatus"/>, safe to surface.</summary>
    public required string ActionDetail { get; init; }

    /// <summary>Documents that were retrieved but rejected as untrusted. Usually empty.</summary>
    public required IReadOnlyList<QuarantinedEvidence> QuarantinedEvidence { get; init; }

    /// <summary>Ties this response to its audit events.</summary>
    public required string CorrelationId { get; init; }
}
