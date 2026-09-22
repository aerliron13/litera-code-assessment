using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Core.Actions;

/// <inheritdoc cref="IActionService"/>
public sealed class ActionService : IActionService
{
    private readonly IReadOnlyDictionary<string, IActionHandler> _handlers;

    public ActionService(IEnumerable<IActionHandler> handlers)
    {
        var registered = new Dictionary<string, IActionHandler>(StringComparer.OrdinalIgnoreCase);

        foreach (var handler in handlers)
        {
            // Two handlers claiming one name would make which gate applies depend on registration
            // order. Refuse at startup rather than resolve it arbitrarily at request time.
            if (!registered.TryAdd(handler.ActionName, handler))
            {
                throw new InvalidOperationException(
                    $"More than one action handler is registered for '{handler.ActionName}'.");
            }
        }

        _handlers = registered;
    }

    public IReadOnlyCollection<string> RegisteredActions => _handlers.Keys.ToArray();

    public IActionHandler? FindHandler(string? action) =>
        string.IsNullOrWhiteSpace(action)
            ? null
            : _handlers.TryGetValue(action.Trim(), out var handler)
                ? handler
                : null;

    public async Task<ActionOutcome> ExecuteAsync(
        ActionExecutionContext context,
        CancellationToken cancellationToken = default)
    {
        var handler = FindHandler(context.Action);

        if (handler is null)
        {
            return ActionOutcome.Unsupported(context.Action);
        }

        // Defence in depth. The orchestrator has already checked this; repeating it here means the
        // check lives with the thing it protects, and a future caller that bypasses the
        // orchestrator does not bypass the role gate with it.
        if (!Roles.Satisfies(context.Role, handler.MinimumRole))
        {
            return ActionOutcome.DeniedInsufficientRole(context.Role, handler.MinimumRole);
        }

        return await handler.ExecuteAsync(context, cancellationToken).ConfigureAwait(false);
    }
}
