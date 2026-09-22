using System.Text.Json.Serialization;
using RegulatedAi.Core.Contracts.Json;

namespace RegulatedAi.Core.Contracts;

/// <summary>
/// The closed set of outcomes for an attempted action. The wire representation is snake_case
/// (for example <c>blocked_pending_approval</c>) to match the required response contract;
/// .NET 7 has no snake_case enum naming policy, so the mapping is explicit in
/// <see cref="ActionStatusJsonConverter"/> rather than inferred.
/// </summary>
[JsonConverter(typeof(ActionStatusJsonConverter))]
public enum ActionStatus
{
    /// <summary>No action was requested; the run was advisory only.</summary>
    NotRequested,

    /// <summary>The action ran. Only reachable once every gate has passed.</summary>
    Executed,

    /// <summary>High-risk action held because no valid approval record exists.</summary>
    BlockedPendingApproval,

    /// <summary>Caller is authenticated for the right tenant but lacks the role to execute.</summary>
    DeniedInsufficientRole,

    /// <summary>No handler is registered for the requested action name. Fails closed.</summary>
    UnsupportedAction,
}
