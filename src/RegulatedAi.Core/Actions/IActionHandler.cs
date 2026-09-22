using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Actions;

/// <summary>
/// One executable action, declaring its own gating requirements alongside its behaviour.
/// </summary>
/// <remarks>
/// <para>
/// Keeping <see cref="MinimumRole"/> and <see cref="AlwaysRequiresApproval"/> on the handler means
/// a new action cannot be added without stating how it is gated — the type system asks the
/// question. The alternative (a switch in the orchestrator) lets someone add an action and forget
/// the gate, which is the failure mode worth designing out.
/// </para>
/// <para>
/// Adding the follow-up exercise's <c>exportPrivilegedSummary</c> is therefore one new class
/// implementing this interface plus one registration line in <c>Program.cs</c>; no change to the
/// orchestrator, the gate, or the audit trail.
/// </para>
/// </remarks>
public interface IActionHandler
{
    /// <summary>The action name as it appears in a request. Matched case-insensitively.</summary>
    string ActionName { get; }

    /// <summary>The lowest role permitted to execute this action.</summary>
    string MinimumRole { get; }

    /// <summary>
    /// When true, this action needs a recorded approval regardless of the assessed risk band.
    /// When false, approval is required only for a high-risk assessment.
    /// </summary>
    bool AlwaysRequiresApproval { get; }

    /// <summary>
    /// Performs the action. Only ever called once the approval gate and the role check have both
    /// passed, and given the *verified* approval record rather than the caller's claim of one.
    /// </summary>
    Task<ActionOutcome> ExecuteAsync(
        ActionExecutionContext context,
        CancellationToken cancellationToken = default);
}
