using Moq;
using RegulatedAi.Core.Actions;
using RegulatedAi.Core.Approvals;
using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Evidence;
using RegulatedAi.Core.Risk;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Core.UnitTests.TestSupport;

/// <summary>
/// Moq setups for every collaborator, so each service is unit-tested against its interfaces alone.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately no seeded corpus here. Wiring the real <c>SeedData</c> into a unit test couples the
/// rule under test to a fixture that exists for the demo, so a change to a seeded document breaks
/// unrelated tests and a rule can pass for reasons that have nothing to do with the rule. Unit
/// tests build the minimum evidence each rule needs; the seeded corpus is exercised end to end by
/// the integration suite, which is where it belongs.
/// </para>
/// <para>
/// Mocks also let a test assert on the <i>arguments</i> a service passed on — "did retrieval get
/// the caller's tenant?" is checkable with <c>Verify</c> rather than inferred from results.
/// </para>
/// </remarks>
public static class Mocked
{
    /// <summary>A clock fixed at <see cref="Now"/>.</summary>
    public static readonly DateTimeOffset Now = new(2026, 1, 15, 9, 0, 0, TimeSpan.Zero);

    public static Mock<IClock> Clock(DateTimeOffset? now = null)
    {
        var clock = new Mock<IClock>();
        clock.SetupGet(instance => instance.UtcNow).Returns(now ?? Now);
        return clock;
    }

    /// <summary>
    /// An <see cref="IAuditService"/> that captures what was written. The captured list is the
    /// assertion target: for an audit trail, *what was recorded* is the interesting question, not
    /// whether a method was called.
    /// </summary>
    public static (Mock<IAuditService> Mock, List<AuditEvent> Written) AuditService()
    {
        var written = new List<AuditEvent>();
        var audit = new Mock<IAuditService>();

        audit
            .Setup(instance => instance.WriteAsync(It.IsAny<AuditEvent>(), It.IsAny<CancellationToken>()))
            .Returns((AuditEvent auditEvent, CancellationToken _) =>
            {
                var stamped = auditEvent with
                {
                    EventId = Guid.NewGuid().ToString("n"),
                    OccurredAtUtc = Now,
                };

                written.Add(stamped);
                return Task.FromResult(stamped);
            });

        audit
            .Setup(instance => instance.GetForTenantAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns((string tenantId, CancellationToken _) =>
                Task.FromResult<IReadOnlyList<AuditEvent>>(
                    written.Where(auditEvent => auditEvent.TenantId == tenantId).ToArray()));

        return (audit, written);
    }

    /// <summary>An <see cref="IEvidenceStore"/> backed by an in-test list, partitioned by tenant.</summary>
    public static Mock<IEvidenceStore> EvidenceStore(params EvidenceDocument[] documents)
    {
        var store = new Mock<IEvidenceStore>();

        store
            .Setup(instance => instance.GetForTenant(It.IsAny<string>()))
            .Returns((string tenantId) => documents
                .Where(document => string.Equals(
                    document.TenantId, tenantId, StringComparison.OrdinalIgnoreCase))
                .ToArray());

        return store;
    }

    /// <summary>An <see cref="IApprovalStore"/> that accumulates appends and reads them back by tenant.</summary>
    public static Mock<IApprovalStore> ApprovalStore()
    {
        var records = new List<ApprovalRecord>();
        var store = new Mock<IApprovalStore>();

        store
            .Setup(instance => instance.Append(It.IsAny<ApprovalRecord>()))
            .Callback((ApprovalRecord record) => records.Add(record));

        store
            .Setup(instance => instance.GetForTenant(It.IsAny<string>()))
            .Returns((string tenantId) => records
                .Where(record => string.Equals(
                    record.TenantId, tenantId, StringComparison.OrdinalIgnoreCase))
                .ToArray());

        return store;
    }

    /// <summary>An <see cref="IAuditStore"/> that accumulates appends and reads them back by tenant.</summary>
    public static Mock<IAuditStore> AuditStore()
    {
        var events = new List<AuditEvent>();
        var store = new Mock<IAuditStore>();

        store
            .Setup(instance => instance.Append(It.IsAny<AuditEvent>()))
            .Callback((AuditEvent auditEvent) => events.Add(auditEvent));

        store
            .Setup(instance => instance.GetForTenant(It.IsAny<string>()))
            .Returns((string tenantId) => events
                .Where(auditEvent => string.Equals(
                    auditEvent.TenantId, tenantId, StringComparison.OrdinalIgnoreCase))
                .ToArray());

        return store;
    }

    /// <summary>Retrieval that returns a fixed set, recording what it was asked for.</summary>
    public static Mock<IEvidenceService> EvidenceService(params EvidenceSnippet[] snippets)
    {
        var evidence = new Mock<IEvidenceService>();

        evidence
            .Setup(instance => instance.SearchEvidenceAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(snippets);

        return evidence;
    }

    /// <summary>A risk service pinned to one band, so orchestrator tests can choose the path.</summary>
    public static Mock<IRiskService> RiskService(RiskLevel level, params Citation[] citations)
    {
        var assessment = new RiskAssessment(
            level,
            PolicyRules.RecommendationFor(level),
            new[] { "stub reason" },
            citations,
            level == RiskLevel.High ? new[] { "SOC 2 report" } : Array.Empty<string>());

        var risk = new Mock<IRiskService>();

        risk
            .Setup(instance => instance.EvaluateRisk(
                It.IsAny<string?>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<EvidenceSnippet>>()))
            .Returns(assessment);

        return risk;
    }

    /// <summary>An approval service with a fixed verdict.</summary>
    public static Mock<IApprovalService> ApprovalServiceDenying(string reason = "no approval on file")
    {
        var approvals = new Mock<IApprovalService>();

        approvals
            .Setup(instance => instance.VerifyApprovalAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ApprovalDecision.Denied(reason));

        return approvals;
    }

    public static Mock<IApprovalService> ApprovalServiceApproving(
        string approver = "dave",
        string tenantId = "tenant-a",
        string action = "markVendorApproved",
        string subjectId = "vendor-x")
    {
        var record = new ApprovalRecord(
            "approval-1", tenantId, action, subjectId, approver, "reviewed", Now);

        var approvals = new Mock<IApprovalService>();

        approvals
            .Setup(instance => instance.VerifyApprovalAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ApprovalDecision.Approved(record));

        return approvals;
    }

    /// <summary>
    /// An action handler with configurable gating metadata.
    /// </summary>
    /// <remarks>
    /// Verifiable through <c>Verify</c> for "did the action run?", which is the assertion the
    /// approval gate tests actually care about.
    /// </remarks>
    public static Mock<IActionHandler> ActionHandler(
        string actionName = "markVendorApproved",
        string minimumRole = Roles.Approver,
        bool alwaysRequiresApproval = false,
        ActionOutcome? outcome = null)
    {
        var handler = new Mock<IActionHandler>();

        handler.SetupGet(instance => instance.ActionName).Returns(actionName);
        handler.SetupGet(instance => instance.MinimumRole).Returns(minimumRole);
        handler.SetupGet(instance => instance.AlwaysRequiresApproval).Returns(alwaysRequiresApproval);

        handler
            .Setup(instance => instance.ExecuteAsync(
                It.IsAny<ActionExecutionContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(outcome ?? ActionOutcome.Executed("mock action executed"));

        return handler;
    }
}

/// <summary>Test data builders. Data, not doubles — these keep the tests readable.</summary>
public static class Build
{
    public static EvidenceDocument Document(
        string documentId,
        string tenantId = "tenant-a",
        string subjectId = "vendor-x",
        string[]? tags = null,
        DateTimeOffset? expiresAtUtc = null,
        string text = "Ordinary compliance prose with no instructions in it.",
        string title = "Document title",
        string documentType = "policy") =>
        new(
            documentId,
            tenantId,
            subjectId,
            title,
            documentType,
            text,
            tags ?? Array.Empty<string>(),
            expiresAtUtc);

    public static EvidenceSnippet Trusted(
        string documentId,
        string[]? tags = null,
        DateTimeOffset? expiresAtUtc = null,
        string subjectId = "vendor-x",
        string snippet = "policy text") =>
        new(
            documentId,
            subjectId,
            $"Title for {documentId}",
            "policy",
            snippet,
            tags ?? Array.Empty<string>(),
            expiresAtUtc,
            IsTrusted: true,
            Array.Empty<string>());

    public static EvidenceSnippet Untrusted(
        string documentId,
        string[]? tags = null,
        string subjectId = "vendor-x",
        params string[] patterns) =>
        new(
            documentId,
            subjectId,
            $"Title for {documentId}",
            "attestation",
            "quarantined text",
            tags ?? Array.Empty<string>(),
            ExpiresAtUtc: null,
            IsTrusted: false,
            patterns.Length > 0 ? patterns : new[] { "ignore-previous-instructions" });

    public static WorkflowRequest Request(
        string tenantId = "tenant-a",
        string userId = "alice",
        string role = Roles.Analyst,
        string question = "Can we approve Vendor X to process customer payment data?",
        string? requestedAction = "markVendorApproved",
        string subjectId = "vendor-x",
        string? approvedBy = null,
        string correlationId = "corr-1") =>
        new(tenantId, userId, role, question, requestedAction, subjectId, approvedBy, correlationId);
}
