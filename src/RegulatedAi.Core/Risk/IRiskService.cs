using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Risk;

/// <summary>
/// The exercise's <c>evaluateRisk</c>. Deterministic and synchronous: no I/O, no ambient state,
/// and its only non-argument input is the injected clock.
/// </summary>
/// <remarks>
/// <para>
/// <b>Where the model would go, and why it is not here.</b> This is the component a real system
/// would be tempted to hand to an LLM. The trust boundary this design draws is that a model may
/// <i>draft</i> the prose — the recommendation sentence, a summary of the gaps — but must never
/// <i>decide</i> <see cref="RiskAssessment.RiskLevel"/>, because that value is what the approval
/// gate consumes. Anything an attacker can influence through retrieved text must not be able to
/// move the gate.
/// </para>
/// <para>
/// So this implementation answers structured questions ("is there a trusted, unexpired document
/// tagged <c>soc2_report</c>?") over data whose tags were assigned at ingestion. Replacing it with
/// a model would mean keeping the tag check and using the model only for wording.
/// </para>
/// </remarks>
public interface IRiskService
{
    /// <summary>
    /// Evaluates the risk of taking <paramref name="requestedAction"/> against
    /// <paramref name="subjectId"/>, given the retrieved evidence.
    /// </summary>
    /// <param name="snippets">
    /// The full retrieved set, including untrusted ones. They are passed in rather than filtered
    /// out beforehand so that this service — the one that decides the band — is also the one that
    /// decides what untrusted content means.
    /// </param>
    RiskAssessment EvaluateRisk(
        string? requestedAction,
        string subjectId,
        IReadOnlyList<EvidenceSnippet> snippets);
}
