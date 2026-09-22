using System.Text.Json;
using System.Text.Json.Serialization;

namespace RegulatedAi.Core.Contracts.Json;

/// <summary>
/// Maps <see cref="ActionStatus"/> to and from its snake_case wire form. The map is exhaustive
/// and explicit: an unrecognised value on the wire is an error rather than a silent default,
/// because "I could not parse the status" must never read as "the action did not run".
/// </summary>
public sealed class ActionStatusJsonConverter : JsonConverter<ActionStatus>
{
    private static readonly IReadOnlyDictionary<ActionStatus, string> ToWire =
        new Dictionary<ActionStatus, string>
        {
            [ActionStatus.NotRequested] = "not_requested",
            [ActionStatus.Executed] = "executed",
            [ActionStatus.BlockedPendingApproval] = "blocked_pending_approval",
            [ActionStatus.DeniedInsufficientRole] = "denied_insufficient_role",
            [ActionStatus.UnsupportedAction] = "unsupported_action",
        };

    private static readonly IReadOnlyDictionary<string, ActionStatus> FromWire =
        ToWire.ToDictionary(pair => pair.Value, pair => pair.Key, StringComparer.OrdinalIgnoreCase);

    /// <summary>The permitted wire values, used by the output-shape validator.</summary>
    public static IReadOnlyCollection<string> AllowedWireValues { get; } = ToWire.Values.ToArray();

    public static string ToWireValue(ActionStatus status) =>
        ToWire.TryGetValue(status, out var wire)
            ? wire
            : throw new ArgumentOutOfRangeException(nameof(status), status, "Unmapped action status.");

    public override ActionStatus Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var raw = reader.GetString();
        if (raw is not null && FromWire.TryGetValue(raw, out var status))
        {
            return status;
        }

        throw new JsonException($"Unrecognised action status '{raw}'.");
    }

    public override void Write(Utf8JsonWriter writer, ActionStatus value, JsonSerializerOptions options) =>
        writer.WriteStringValue(ToWireValue(value));
}
