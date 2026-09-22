using System.Text.Json;
using System.Text.Json.Serialization;

namespace RegulatedAi.Api.Contracts;

/// <summary>
/// The service's JSON contract, in one place.
/// </summary>
/// <remarks>
/// <para>
/// Extracted from <c>Program.cs</c> so the published wire format can be asserted by a test. It is
/// here because of a real bug: a global
/// <c>JsonStringEnumConverter(JsonNamingPolicy.CamelCase)</c> was registered in
/// <c>Converters</c>, and converters in that collection take precedence over a
/// <c>[JsonConverter]</c> attribute on the type. The per-enum converters were therefore never
/// consulted, and <c>actionStatus</c> went out as <c>blockedPendingApproval</c> instead of the
/// contracted <c>blocked_pending_approval</c> — silently, with nothing failing.
/// </para>
/// <para>
/// The fix is the absence of a global enum converter. Every enum that appears on the wire declares
/// its own, and <c>WireContractTests</c> asserts the resulting strings.
/// </para>
/// </remarks>
public static class RegulatedAiJsonOptions
{
    /// <summary>Applies the service's JSON conventions to an options instance.</summary>
    public static void Configure(JsonSerializerOptions options)
    {
        options.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    }

    /// <summary>A standalone instance carrying the same conventions, for tests and tooling.</summary>
    public static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions();
        Configure(options);
        return options;
    }
}
