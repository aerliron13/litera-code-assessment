namespace RegulatedAi.Core.Contracts;

/// <summary>
/// The caller sent something the engine will not act on. Maps to HTTP 400. Distinct from
/// <see cref="WorkflowContractViolationException"/>, which means *we* produced something wrong.
/// </summary>
public sealed class InvalidWorkflowRequestException : Exception
{
    public InvalidWorkflowRequestException(string message) : base(message)
    {
    }
}

/// <summary>
/// The engine built a response that breaks its own invariants. Maps to HTTP 500, and never to a
/// partial response: a result we cannot vouch for is not returned at all, because the failure
/// modes this catches include leaking another tenant's citation.
/// </summary>
public sealed class WorkflowContractViolationException : Exception
{
    public WorkflowContractViolationException(IReadOnlyList<string> violations)
        : base("The workflow produced a response that violates its output contract.")
    {
        Violations = violations;
    }

    public IReadOnlyList<string> Violations { get; }
}
