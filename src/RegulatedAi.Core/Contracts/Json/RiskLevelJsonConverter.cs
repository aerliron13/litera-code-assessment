using System.Text.Json;
using System.Text.Json.Serialization;

namespace RegulatedAi.Core.Contracts.Json;

/// <summary>
/// Maps <see cref="RiskLevel"/> to and from its lowercase wire form.
/// </summary>
/// <remarks>
/// <para>
/// Explicit rather than a <see cref="JsonStringEnumConverter"/> with a camelCase policy, for a
/// reason worth knowing: converters registered in <c>JsonSerializerOptions.Converters</c> take
/// precedence over a <c>[JsonConverter]</c> attribute on the type. A global enum converter
/// therefore silently overrides the per-type converter that
/// <see cref="ActionStatusJsonConverter"/> exists to provide, and <c>blocked_pending_approval</c>
/// goes out as <c>blockedPendingApproval</c> — a broken contract with no error anywhere.
/// </para>
/// <para>
/// So there is no global enum converter in this service. Every enum on the wire declares its own,
/// and the mapping is a table you can read.
/// </para>
/// </remarks>
public sealed class RiskLevelJsonConverter : JsonConverter<RiskLevel>
{
    private static readonly IReadOnlyDictionary<RiskLevel, string> ToWire =
        new Dictionary<RiskLevel, string>
        {
            [RiskLevel.Low] = "low",
            [RiskLevel.Medium] = "medium",
            [RiskLevel.High] = "high",
        };

    private static readonly IReadOnlyDictionary<string, RiskLevel> FromWire =
        ToWire.ToDictionary(pair => pair.Value, pair => pair.Key, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyCollection<string> AllowedWireValues { get; } = ToWire.Values.ToArray();

    public static string ToWireValue(RiskLevel level) =>
        ToWire.TryGetValue(level, out var wire)
            ? wire
            : throw new ArgumentOutOfRangeException(nameof(level), level, "Unmapped risk level.");

    public override RiskLevel Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var raw = reader.GetString();
        if (raw is not null && FromWire.TryGetValue(raw, out var level))
        {
            return level;
        }

        throw new JsonException($"Unrecognised risk level '{raw}'.");
    }

    public override void Write(Utf8JsonWriter writer, RiskLevel value, JsonSerializerOptions options) =>
        writer.WriteStringValue(ToWireValue(value));
}
