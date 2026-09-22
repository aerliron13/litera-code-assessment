using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Actions;

/// <summary>
/// The exercise's <c>executeMockAction</c>, plus the registry the orchestrator consults to learn
/// how an action is gated before it decides whether to run it.
/// </summary>
public interface IActionService
{
    /// <summary>
    /// The handler for an action name, or null when none is registered. The orchestrator needs
    /// this *before* execution to read the gating metadata.
    /// </summary>
    IActionHandler? FindHandler(string? action);

    /// <summary>The registered action names, exposed for discoverability.</summary>
    IReadOnlyCollection<string> RegisteredActions { get; }

    /// <summary>
    /// Executes an action. Re-checks the role and refuses an unknown action, so the gates hold
    /// even if a future caller reaches this service without going through the orchestrator.
    /// </summary>
    Task<ActionOutcome> ExecuteAsync(
        ActionExecutionContext context,
        CancellationToken cancellationToken = default);
}
