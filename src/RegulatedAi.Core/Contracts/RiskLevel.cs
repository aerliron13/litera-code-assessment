using System.Text.Json.Serialization;
using RegulatedAi.Core.Contracts.Json;

namespace RegulatedAi.Core.Contracts;

/// <summary>
/// Risk bands, ordered deliberately so that escalation can be expressed as a comparison
/// (see <see cref="RiskLevelExtensions.Escalate"/>). Nothing in the engine may ever *lower* a
/// risk level.
/// </summary>
[JsonConverter(typeof(RiskLevelJsonConverter))]
public enum RiskLevel
{
    Low = 0,
    Medium = 1,
    High = 2,
}

public static class RiskLevelExtensions
{
    /// <summary>
    /// Returns the higher of the two levels. Risk only ever ratchets upwards: a rule that
    /// could lower a previously-established level would be an escalation-bypass primitive.
    /// </summary>
    public static RiskLevel Escalate(this RiskLevel current, RiskLevel candidate) =>
        candidate > current ? candidate : current;
}
