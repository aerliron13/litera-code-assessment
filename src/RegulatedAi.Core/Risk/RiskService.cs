using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;

namespace RegulatedAi.Core.Risk;

/// <inheritdoc cref="IRiskService"/>
public sealed class RiskService : IRiskService
{
    private const string NoGapsReason = "All required evidence is present and current.";

    private readonly IClock _clock;

    public RiskService(IClock clock) => _clock = clock;

    public RiskAssessment EvaluateRisk(
        string? requestedAction,
        string subjectId,
        IReadOnlyList<EvidenceSnippet> snippets)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new ArgumentException("A subject id is required.", nameof(subjectId));
        }

        var asOf = _clock.UtcNow;

        // Untrusted content is dropped here, once, before any rule sees it. Everything below this
        // line therefore reasons only over content that passed screening — a quarantined document
        // cannot satisfy a requirement, and so cannot lower the band.
        var trusted = snippets.Where(snippet => snippet.IsTrusted).ToArray();
        var quarantinedCount = snippets.Count - trusted.Length;

        var reasons = new List<string>();
        var missingEvidence = new List<string>();
        var citations = new List<Citation>();
        var citedDocumentIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Cite(EvidenceSnippet snippet)
        {
            if (citedDocumentIds.Add(snippet.DocumentId))
            {
                citations.Add(new Citation(snippet.DocumentId, snippet.Snippet));
            }
        }

        // Cite the governing policy first, so the answer leads with the rule it applied rather
        // than with the evidence it happened to find.
        CiteAllTagged(trusted, EvidenceTags.PaymentVendorRequirements, Cite);
        CiteAllTagged(trusted, EvidenceTags.VendorApprovalPolicy, Cite);

        var anyMissing = false;
        var anyExpired = false;

        foreach (var requirement in PolicyRules.ForAction(requestedAction))
        {
            var tagged = trusted.Where(snippet => snippet.HasTag(requirement.Tag)).ToArray();
            var current = tagged.Where(snippet => !snippet.IsExpiredAt(asOf)).ToArray();

            if (current.Length > 0)
            {
                foreach (var snippet in current)
                {
                    Cite(snippet);
                }

                continue;
            }

            if (tagged.Length > 0)
            {
                // The evidence exists but has lapsed. Cite the lapsed document: "your SOC 2
                // expired" is a materially different finding from "you never gave us one", and the
                // reader needs to see which document the engine is talking about.
                anyExpired = true;
                reasons.Add(requirement.ExpiredReason);
                missingEvidence.Add($"current {requirement.MissingLabel}");

                foreach (var snippet in tagged)
                {
                    Cite(snippet);
                }

                continue;
            }

            anyMissing = true;
            reasons.Add(requirement.MissingReason);
            missingEvidence.Add(requirement.MissingLabel);
        }

        // When there is a gap, cite the governing contract too — it is the document that shows the
        // clause is absent, which is what makes the finding checkable by a human.
        if (anyMissing || anyExpired)
        {
            CiteAllTagged(trusted, EvidenceTags.VendorContract, Cite);
        }

        var riskLevel = anyMissing
            ? RiskLevel.High
            : anyExpired
                ? RiskLevel.Medium
                : RiskLevel.Low;

        if (quarantinedCount > 0)
        {
            reasons.Add(PolicyRules.QuarantineReason);
            riskLevel = riskLevel.Escalate(PolicyRules.QuarantineFloor);
        }

        if (reasons.Count == 0)
        {
            reasons.Add(NoGapsReason);
        }

        return new RiskAssessment(
            riskLevel,
            PolicyRules.RecommendationFor(riskLevel),
            reasons,
            citations,
            missingEvidence);
    }

    private static void CiteAllTagged(
        IReadOnlyList<EvidenceSnippet> trusted,
        string tag,
        Action<EvidenceSnippet> cite)
    {
        foreach (var snippet in trusted.Where(snippet => snippet.HasTag(tag)))
        {
            cite(snippet);
        }
    }
}
