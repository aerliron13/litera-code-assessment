using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Contracts.Json;

namespace RegulatedAi.Core.UnitTests;

/// <summary>
/// One test per invariant. The validator is the last line of defence before a response leaves the
/// process, so each rule is checked in isolation rather than through a whole workflow run.
/// </summary>
public sealed class WorkflowResultValidatorTests
{
    private const string Retrieved = "policy-a-002";
    private const string Quarantined = "evidence-a-666";

    private static WorkflowValidationContext Context(
        string? requestedAction = "markVendorApproved",
        bool approvalVerified = true) =>
        new(
            "tenant-a",
            requestedAction,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Retrieved, Quarantined },
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Quarantined },
            approvalVerified);

    private static WorkflowResult Valid(
        RiskLevel riskLevel = RiskLevel.High,
        ActionStatus actionStatus = ActionStatus.Executed,
        bool requiresApproval = true,
        Citation[]? citations = null,
        QuarantinedEvidence[]? quarantined = null,
        string recommendation = "Do not approve yet.",
        string correlationId = "corr-1",
        string[]? reasons = null,
        string[]? missingEvidence = null) =>
        new()
        {
            RiskLevel = riskLevel,
            Recommendation = recommendation,
            Reasons = reasons ?? new[] { "No SOC 2 evidence found." },
            Citations = citations ?? new[] { new Citation(Retrieved, "requirement text") },
            MissingEvidence = missingEvidence ?? new[] { "SOC 2 report" },
            RequiresApproval = requiresApproval,
            ActionStatus = actionStatus,
            ActionDetail = "detail",
            QuarantinedEvidence = quarantined ?? Array.Empty<QuarantinedEvidence>(),
            CorrelationId = correlationId,
        };

    [Fact]
    public void Accepts_a_well_formed_result() =>
        Assert.Empty(WorkflowResultValidator.Inspect(Valid(), Context()));

    [Fact]
    public void Validate_does_not_throw_for_a_well_formed_result() =>
        WorkflowResultValidator.Validate(Valid(), Context());

    // ---------------------------------------------------------------------------------------
    // Tenant-leak backstop
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The invariant that matters most: retrieval is already tenant-scoped, so a citation it never
    /// returned either came from another tenant or was fabricated. Both are refusals.
    /// </summary>
    [Fact]
    public void Rejects_a_citation_that_retrieval_did_not_return()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(citations: new[] { new Citation("policy-b-002", "another tenant's policy") }),
            Context());

        Assert.Contains(violations, violation => violation.Contains("policy-b-002"));
    }

    [Fact]
    public void Rejects_a_citation_of_quarantined_content()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(citations: new[] { new Citation(Quarantined, "ignore previous instructions") }),
            Context());

        Assert.Contains(violations, violation => violation.Contains("quarantined"));
    }

    [Theory]
    [InlineData("", "snippet")]
    [InlineData("doc", "")]
    [InlineData("   ", "   ")]
    public void Rejects_an_incomplete_citation(string documentId, string snippet)
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(citations: new[] { new Citation(documentId, snippet) }),
            Context());

        Assert.NotEmpty(violations);
    }

    // ---------------------------------------------------------------------------------------
    // Gate invariants
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Rejects_high_risk_that_does_not_require_approval()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(riskLevel: RiskLevel.High, requiresApproval: false),
            Context());

        Assert.Contains(violations, violation => violation.Contains("requiresApproval"));
    }

    [Fact]
    public void Rejects_execution_without_a_verified_approval_when_approval_was_required()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(actionStatus: ActionStatus.Executed, requiresApproval: true),
            Context(approvalVerified: false));

        Assert.Contains(violations, violation => violation.Contains("verified approval"));
    }

    [Fact]
    public void Allows_execution_without_an_approval_when_none_was_required()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(riskLevel: RiskLevel.Low, actionStatus: ActionStatus.Executed, requiresApproval: false),
            Context(approvalVerified: false));

        Assert.Empty(violations);
    }

    [Fact]
    public void Rejects_execution_when_no_action_was_requested()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(actionStatus: ActionStatus.Executed),
            Context(requestedAction: null));

        Assert.Contains(violations, violation => violation.Contains("no action was requested"));
    }

    [Fact]
    public void Rejects_not_requested_when_an_action_was_requested()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(actionStatus: ActionStatus.NotRequested),
            Context(requestedAction: "markVendorApproved"));

        Assert.Contains(violations, violation => violation.Contains("not_requested"));
    }

    [Fact]
    public void Accepts_not_requested_on_an_advisory_run()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(actionStatus: ActionStatus.NotRequested),
            Context(requestedAction: null));

        Assert.Empty(violations);
    }

    [Fact]
    public void Accepts_a_blocked_action()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(actionStatus: ActionStatus.BlockedPendingApproval),
            Context(approvalVerified: false));

        Assert.Empty(violations);
    }

    // ---------------------------------------------------------------------------------------
    // Shape invariants
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Rejects_an_empty_recommendation(string recommendation)
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(recommendation: recommendation),
            Context());

        Assert.Contains(violations, violation => violation.Contains("recommendation"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Rejects_a_missing_correlation_id(string correlationId)
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(correlationId: correlationId),
            Context());

        Assert.Contains(violations, violation => violation.Contains("correlationId"));
    }

    [Fact]
    public void Rejects_an_undefined_risk_level()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(riskLevel: (RiskLevel)99),
            Context());

        Assert.Contains(violations, violation => violation.Contains("risk band"));
    }

    [Fact]
    public void Rejects_an_undefined_action_status()
    {
        // Enum.IsDefined runs before the wire-value lookup, so an out-of-range status is reported
        // rather than throwing out of the converter.
        var violations = WorkflowResultValidator.Inspect(
            Valid(actionStatus: (ActionStatus)99),
            Context());

        Assert.Contains(violations, violation => violation.Contains("action status"));
    }

    [Fact]
    public void Rejects_empty_reasons()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(reasons: new[] { "a good reason", "   " }),
            Context());

        Assert.Contains(violations, violation => violation.Contains("reasons"));
    }

    [Fact]
    public void Rejects_empty_missing_evidence_entries()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(missingEvidence: new[] { "" }),
            Context());

        Assert.Contains(violations, violation => violation.Contains("missingEvidence"));
    }

    [Fact]
    public void Rejects_quarantined_evidence_with_no_stated_reason()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(quarantined: new[] { new QuarantinedEvidence(Quarantined, Array.Empty<string>()) }),
            Context());

        Assert.Contains(violations, violation => violation.Contains("why it was rejected"));
    }

    [Fact]
    public void Collects_every_violation_rather_than_stopping_at_the_first()
    {
        var violations = WorkflowResultValidator.Inspect(
            Valid(
                riskLevel: RiskLevel.High,
                requiresApproval: false,
                recommendation: "",
                citations: new[] { new Citation("not-retrieved", "text") }),
            Context());

        Assert.True(violations.Count >= 3, $"Expected several violations, got {violations.Count}.");
    }

    [Fact]
    public void Validate_throws_and_carries_the_violations()
    {
        var exception = Assert.Throws<WorkflowContractViolationException>(
            () => WorkflowResultValidator.Validate(
                Valid(citations: new[] { new Citation("not-retrieved", "text") }),
                Context()));

        Assert.NotEmpty(exception.Violations);
    }

    // ---------------------------------------------------------------------------------------
    // Wire contract
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ActionStatus.NotRequested, "not_requested")]
    [InlineData(ActionStatus.Executed, "executed")]
    [InlineData(ActionStatus.BlockedPendingApproval, "blocked_pending_approval")]
    [InlineData(ActionStatus.DeniedInsufficientRole, "denied_insufficient_role")]
    [InlineData(ActionStatus.UnsupportedAction, "unsupported_action")]
    public void Every_action_status_has_the_expected_wire_form(ActionStatus status, string expected) =>
        Assert.Equal(expected, ActionStatusJsonConverter.ToWireValue(status));

    [Fact]
    public void Every_declared_action_status_is_mapped()
    {
        foreach (var status in Enum.GetValues<ActionStatus>())
        {
            Assert.False(string.IsNullOrWhiteSpace(ActionStatusJsonConverter.ToWireValue(status)));
        }
    }
}
