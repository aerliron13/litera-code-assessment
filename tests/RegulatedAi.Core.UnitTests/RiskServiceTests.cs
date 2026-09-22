using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Risk;
using RegulatedAi.Core.UnitTests.TestSupport;

namespace RegulatedAi.Core.UnitTests;

/// <summary>
/// The risk rules, tested directly. Each test builds only the evidence its rule needs, so a
/// failure names exactly one rule.
/// </summary>
public sealed class RiskServiceTests
{
    private const string Action = "markVendorApproved";
    private const string Subject = "vendor-x";

    private readonly DateTimeOffset _now = Mocked.Now;
    private readonly RiskService _service = new(Mocked.Clock().Object);

    private static readonly string[] AllRequirementTags =
    {
        EvidenceTags.Soc2Report,
        EvidenceTags.DataRetentionSchedule,
        EvidenceTags.BreachNotificationClause,
    };

    private EvidenceSnippet[] CompleteAndCurrent() => AllRequirementTags
        .Select((tag, index) => Build.Trusted($"doc-{index}", new[] { tag }, _now.AddMonths(6)))
        .ToArray();

    // ---------------------------------------------------------------------------------------
    // Bands
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Missing_evidence_is_high_risk()
    {
        var assessment = _service.EvaluateRisk(
            Action,
            Subject,
            new[] { Build.Trusted("policy-1", new[] { EvidenceTags.PaymentVendorRequirements }) });

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Equal("Do not approve yet.", assessment.Recommendation);
        Assert.Equal(3, assessment.MissingEvidence.Count);
    }

    [Fact]
    public void Complete_and_current_evidence_is_low_risk()
    {
        var assessment = _service.EvaluateRisk(Action, Subject, CompleteAndCurrent());

        Assert.Equal(RiskLevel.Low, assessment.RiskLevel);
        Assert.Empty(assessment.MissingEvidence);
    }

    [Fact]
    public void One_missing_requirement_out_of_three_is_still_high_risk()
    {
        var snippets = new[]
        {
            Build.Trusted("soc2", new[] { EvidenceTags.Soc2Report }),
            Build.Trusted("retention", new[] { EvidenceTags.DataRetentionSchedule }),
            // No breach notification clause.
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Equal("breach notification clause", Assert.Single(assessment.MissingEvidence));
        Assert.Contains("Contract lacks breach notification language.", assessment.Reasons);
    }

    [Fact]
    public void Expired_evidence_is_medium_risk_not_high()
    {
        var snippets = new[]
        {
            Build.Trusted("soc2", new[] { EvidenceTags.Soc2Report }, _now.AddDays(-1)),
            Build.Trusted("retention", new[] { EvidenceTags.DataRetentionSchedule }),
            Build.Trusted("breach", new[] { EvidenceTags.BreachNotificationClause }),
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        // "You had one and it lapsed" is a materially different finding from "you never had one".
        Assert.Equal(RiskLevel.Medium, assessment.RiskLevel);
        Assert.Contains("current SOC 2 report", assessment.MissingEvidence);
        Assert.Contains(assessment.Reasons, reason => reason.Contains("lapsed"));
    }

    [Fact]
    public void A_missing_requirement_outweighs_a_merely_expired_one()
    {
        var snippets = new[]
        {
            Build.Trusted("soc2", new[] { EvidenceTags.Soc2Report }, _now.AddDays(-1)),
            Build.Trusted("retention", new[] { EvidenceTags.DataRetentionSchedule }),
            // No breach clause at all.
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
    }

    [Fact]
    public void Evidence_expiring_exactly_now_is_treated_as_expired()
    {
        var snippets = AllRequirementTags
            .Select((tag, index) => Build.Trusted($"doc-{index}", new[] { tag }, _now))
            .ToArray();

        Assert.Equal(RiskLevel.Medium, _service.EvaluateRisk(Action, Subject, snippets).RiskLevel);
    }

    [Fact]
    public void A_second_current_document_satisfies_a_requirement_despite_a_lapsed_one()
    {
        var snippets = new[]
        {
            Build.Trusted("soc2-old", new[] { EvidenceTags.Soc2Report }, _now.AddDays(-1)),
            Build.Trusted("soc2-new", new[] { EvidenceTags.Soc2Report }, _now.AddMonths(6)),
            Build.Trusted("retention", new[] { EvidenceTags.DataRetentionSchedule }),
            Build.Trusted("breach", new[] { EvidenceTags.BreachNotificationClause }),
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Equal(RiskLevel.Low, assessment.RiskLevel);
    }

    [Fact]
    public void A_document_with_no_expiry_never_lapses()
    {
        var snippets = AllRequirementTags
            .Select((tag, index) => Build.Trusted($"doc-{index}", new[] { tag }))
            .ToArray();

        Assert.Equal(RiskLevel.Low, _service.EvaluateRisk(Action, Subject, snippets).RiskLevel);
    }

    // ---------------------------------------------------------------------------------------
    // Prompt injection: the behaviourally meaningful case
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The central prompt-injection assertion. The untrusted document claims all three requirement
    /// tags, so if quarantined content could satisfy a requirement this subject would come back
    /// <b>low</b> risk. It must come back high.
    /// </summary>
    [Fact]
    public void Untrusted_evidence_cannot_satisfy_a_requirement()
    {
        var snippets = new[]
        {
            Build.Trusted("policy-1", new[] { EvidenceTags.PaymentVendorRequirements }),
            Build.Untrusted("evidence-666", AllRequirementTags),
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Equal(3, assessment.MissingEvidence.Count);
    }

    [Fact]
    public void Untrusted_evidence_is_never_cited()
    {
        var snippets = new[]
        {
            Build.Trusted("policy-1", new[] { EvidenceTags.PaymentVendorRequirements }),
            Build.Untrusted("evidence-666", AllRequirementTags),
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.DoesNotContain(assessment.Citations, citation => citation.DocumentId == "evidence-666");
    }

    /// <summary>
    /// Quarantined content raises the floor even when every requirement is met: the corpus cannot
    /// be taken at face value, which is a human-review trigger rather than a rejection.
    /// </summary>
    [Fact]
    public void Quarantined_content_raises_an_otherwise_low_assessment_to_the_quarantine_floor()
    {
        var snippets = CompleteAndCurrent().Append(Build.Untrusted("evidence-666")).ToArray();

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Equal(PolicyRules.QuarantineFloor, assessment.RiskLevel);
        Assert.Contains(PolicyRules.QuarantineReason, assessment.Reasons);
    }

    [Fact]
    public void Quarantined_content_never_lowers_an_existing_high_assessment()
    {
        var snippets = new[]
        {
            Build.Trusted("policy-1", new[] { EvidenceTags.PaymentVendorRequirements }),
            Build.Untrusted("evidence-666", AllRequirementTags),
        };

        Assert.Equal(RiskLevel.High, _service.EvaluateRisk(Action, Subject, snippets).RiskLevel);
    }

    [Fact]
    public void A_clean_corpus_adds_no_quarantine_reason()
    {
        var assessment = _service.EvaluateRisk(Action, Subject, CompleteAndCurrent());

        Assert.DoesNotContain(PolicyRules.QuarantineReason, assessment.Reasons);
    }

    // ---------------------------------------------------------------------------------------
    // Citations
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Cites_the_governing_policy_first()
    {
        var snippets = new[]
        {
            Build.Trusted("soc2", new[] { EvidenceTags.Soc2Report }),
            Build.Trusted("policy-1", new[] { EvidenceTags.PaymentVendorRequirements }),
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Equal("policy-1", assessment.Citations[0].DocumentId);
    }

    [Fact]
    public void Cites_the_contract_when_a_clause_is_missing()
    {
        var snippets = new[]
        {
            Build.Trusted("policy-1", new[] { EvidenceTags.PaymentVendorRequirements }),
            Build.Trusted("contract-1", new[] { EvidenceTags.VendorContract }),
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        // The contract is what evidences the *absence* of the clause, so a human can check it.
        Assert.Contains(assessment.Citations, citation => citation.DocumentId == "contract-1");
    }

    [Fact]
    public void Does_not_cite_the_contract_when_there_is_nothing_to_explain()
    {
        var snippets = CompleteAndCurrent()
            .Append(Build.Trusted("contract-1", new[] { EvidenceTags.VendorContract }))
            .ToArray();

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Equal(RiskLevel.Low, assessment.RiskLevel);
        Assert.DoesNotContain(assessment.Citations, citation => citation.DocumentId == "contract-1");
    }

    [Fact]
    public void Does_not_cite_the_same_document_twice()
    {
        var snippets = new[]
        {
            Build.Trusted(
                "combined",
                new[] { EvidenceTags.PaymentVendorRequirements, EvidenceTags.VendorApprovalPolicy }),
        };

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.Single(assessment.Citations.Where(citation => citation.DocumentId == "combined"));
    }

    [Fact]
    public void Citations_only_ever_come_from_the_supplied_snippets()
    {
        var snippets = new[]
        {
            Build.Trusted("policy-1", new[] { EvidenceTags.PaymentVendorRequirements }),
            Build.Trusted("soc2", new[] { EvidenceTags.Soc2Report }),
        };

        var supplied = snippets.Select(snippet => snippet.DocumentId).ToHashSet();

        var assessment = _service.EvaluateRisk(Action, Subject, snippets);

        Assert.All(assessment.Citations, citation => Assert.Contains(citation.DocumentId, supplied));
    }

    [Fact]
    public void Every_citation_carries_a_snippet()
    {
        var assessment = _service.EvaluateRisk(Action, Subject, CompleteAndCurrent());

        Assert.NotEmpty(assessment.Citations);
        Assert.All(assessment.Citations, citation => Assert.False(
            string.IsNullOrWhiteSpace(citation.Snippet)));
    }

    // ---------------------------------------------------------------------------------------
    // Fail-closed behaviour
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void No_evidence_at_all_is_high_risk()
    {
        var assessment = _service.EvaluateRisk(Action, Subject, Array.Empty<EvidenceSnippet>());

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Empty(assessment.Citations);
    }

    /// <summary>
    /// An action with no rules of its own still gets the full requirement set — otherwise adding
    /// an action and forgetting its rules would yield an unconditional low-risk verdict.
    /// </summary>
    [Fact]
    public void An_unknown_action_still_gets_the_full_requirement_set()
    {
        var assessment = _service.EvaluateRisk(
            "someActionNobodyDefined", Subject, Array.Empty<EvidenceSnippet>());

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Equal(PolicyRules.PaymentVendorRequirements.Count, assessment.MissingEvidence.Count);
    }

    [Fact]
    public void An_advisory_run_with_no_action_is_assessed_just_as_strictly() =>
        Assert.Equal(
            RiskLevel.High,
            _service.EvaluateRisk(null, Subject, Array.Empty<EvidenceSnippet>()).RiskLevel);

    [Fact]
    public void A_document_with_no_tags_satisfies_nothing()
    {
        var assessment = _service.EvaluateRisk(
            Action, Subject, new[] { Build.Trusted("untagged") });

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Equal(3, assessment.MissingEvidence.Count);
    }

    [Fact]
    public void Always_produces_at_least_one_reason()
    {
        var assessment = _service.EvaluateRisk(Action, Subject, CompleteAndCurrent());

        Assert.NotEmpty(assessment.Reasons);
    }

    [Theory]
    [InlineData(RiskLevel.Low)]
    [InlineData(RiskLevel.Medium)]
    [InlineData(RiskLevel.High)]
    public void Every_band_has_a_recommendation(RiskLevel level) =>
        Assert.False(string.IsNullOrWhiteSpace(PolicyRules.RecommendationFor(level)));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Requires_a_subject_id(string? subjectId) =>
        Assert.Throws<ArgumentException>(
            () => _service.EvaluateRisk(Action, subjectId!, Array.Empty<EvidenceSnippet>()));

    // ---------------------------------------------------------------------------------------
    // Escalation primitive
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(RiskLevel.Low, RiskLevel.High, RiskLevel.High)]
    [InlineData(RiskLevel.High, RiskLevel.Low, RiskLevel.High)]
    [InlineData(RiskLevel.Medium, RiskLevel.Medium, RiskLevel.Medium)]
    [InlineData(RiskLevel.High, RiskLevel.Medium, RiskLevel.High)]
    public void Escalation_only_ever_ratchets_upwards(
        RiskLevel current,
        RiskLevel candidate,
        RiskLevel expected) =>
        Assert.Equal(expected, current.Escalate(candidate));
}
