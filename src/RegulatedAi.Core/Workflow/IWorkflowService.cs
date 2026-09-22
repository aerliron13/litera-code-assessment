using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Workflow;

/// <summary>
/// The exercise's <c>runWorkflow</c>: retrieve evidence, evaluate risk, gate the action, audit
/// everything, and return a validated cited recommendation.
/// </summary>
/// <remarks>
/// The orchestrator sequences the other services and owns no rules of its own — risk rules live in
/// the risk layer, gating metadata on the action handler, approval semantics in the approval
/// service. What it does own is the guarantee that the steps happen in the right order and that
/// the audit trail is written on every path, including every failure path.
/// </remarks>
public interface IWorkflowService
{
    /// <exception cref="InvalidWorkflowRequestException">The request is not actionable.</exception>
    /// <exception cref="WorkflowContractViolationException">
    /// The engine produced a response that breaks its own invariants. Never returned to a caller
    /// as a partial result.
    /// </exception>
    Task<WorkflowResult> RunWorkflowAsync(
        WorkflowRequest request,
        CancellationToken cancellationToken = default);
}
