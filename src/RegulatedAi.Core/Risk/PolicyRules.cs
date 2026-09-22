using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;

namespace RegulatedAi.Core.Risk;

/// <summary>
/// One piece of evidence a policy demands, together with the wording used when it is absent.
/// </summary>
/// <param name="Tag">The structured tag that satisfies this requirement.</param>
/// <param name="MissingLabel">How the gap is named in <c>missingEvidence</c>.</param>
/// <param name="MissingReason">How the gap is explained in <c>reasons</c>.</param>
/// <param name="ExpiredReason">How a lapsed document is explained.</param>
public sealed record EvidenceRequirement(
    string Tag,
    string MissingLabel,
    string MissingReason,
    string ExpiredReason);

/// <summary>
/// The rule set. A deliberately small function with explicit rules, as the brief asks — not a
/// policy engine.
/// </summary>
/// <remarks>
/// This is the seam where a real deployment diverges most. Requirements would be versioned data
/// owned by compliance, not constants in a C# file, and every decision would record *which
/// version* of the rules produced it so an old decision stays explicable after the rules change.
/// The shape here (requirements in, reasons and citations out) is what makes that swap local.
/// </remarks>
public static class PolicyRules
{
    /// <summary>
    /// The evidence a payment-data vendor must have before it can be approved. Mirrors the seeded
    /// requirement policy documents, which are what the engine cites.
    /// </summary>
    public static IReadOnlyList<EvidenceRequirement> PaymentVendorRequirements { get; } = new[]
    {
        new EvidenceRequirement(
            EvidenceTags.Soc2Report,
            "SOC 2 report",
            "No SOC 2 evidence found.",
            "The SOC 2 report on file has lapsed."),

        new EvidenceRequirement(
            EvidenceTags.DataRetentionSchedule,
            "data retention schedule",
            "No data retention schedule found.",
            "The data retention schedule on file has lapsed."),

        new EvidenceRequirement(
            EvidenceTags.BreachNotificationClause,
            "breach notification clause",
            "Contract lacks breach notification language.",
            "The breach notification commitment on file has lapsed."),
    };

    /// <summary>
    /// The requirements that apply to an action.
    /// </summary>
    /// <remarks>
    /// Fails closed in two directions. A request with no action still gets the full requirement
    /// set, so an advisory answer is no more generous than an action would be; and an unrecognised
    /// action also gets the full set rather than an empty one, so adding an action name without
    /// adding rules cannot produce an unconditionally low-risk verdict.
    /// </remarks>
    public static IReadOnlyList<EvidenceRequirement> ForAction(string? action) => action switch
    {
        ActionNames.MarkVendorApproved => PaymentVendorRequirements,
        _ => PaymentVendorRequirements,
    };

    /// <summary>The recommendation wording for each band.</summary>
    public static string RecommendationFor(RiskLevel level) => level switch
    {
        RiskLevel.High => "Do not approve yet.",
        RiskLevel.Medium => "Do not approve without human review of the gaps below.",
        RiskLevel.Low => "Approve. Required evidence is present and current.",
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unmapped risk level."),
    };

    /// <summary>
    /// Added whenever retrieved content was quarantined. See <see cref="QuarantineFloor"/> for
    /// why this also moves the band.
    /// </summary>
    public const string QuarantineReason =
        "Untrusted content was detected in the retrieved evidence and excluded from scoring.";

    /// <summary>
    /// The lowest band a subject may be assigned once any of its evidence has been quarantined.
    /// </summary>
    /// <remarks>
    /// Medium, not high. Injected content in the corpus does not by itself say the vendor is
    /// unsafe — it says the evidence about the vendor cannot be taken at face value, which is a
    /// human-review trigger rather than a rejection. A stricter deployment could reasonably set
    /// this to <see cref="RiskLevel.High"/>; THREAT_NOTES.md records that trade-off. Either way it
    /// only ever raises the band: quarantined content can never lower risk, because quarantined
    /// documents satisfy no requirement.
    /// </remarks>
    public const RiskLevel QuarantineFloor = RiskLevel.Medium;
}
