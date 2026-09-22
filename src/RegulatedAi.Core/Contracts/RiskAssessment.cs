namespace RegulatedAi.Core.Contracts;

/// <summary>
/// The output of the risk layer. In a deployment that used a real model this is the shape the
/// model would be constrained to produce, and it would still be re-validated here — the model
/// would be a *suggestion engine*, never the authority on <see cref="RiskLevel"/>.
/// </summary>
public sealed record RiskAssessment(
    RiskLevel RiskLevel,
    string Recommendation,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<Citation> Citations,
    IReadOnlyList<string> MissingEvidence);
