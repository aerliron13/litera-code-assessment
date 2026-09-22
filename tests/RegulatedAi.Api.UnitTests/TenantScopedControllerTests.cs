using Microsoft.AspNetCore.Mvc;
using Moq;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Api.Controllers;
using RegulatedAi.Api.UnitTests.TestSupport;
using RegulatedAi.Core.Approvals;
using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Evidence;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.UnitTests;

/// <summary>
/// The remaining tenant-scoped controllers. Each one is thin, and each one is tested for the same
/// property: it asks its service about the caller's own tenant, taken from claims.
/// </summary>
public sealed class ApprovalsControllerTests
{
    private readonly Mock<IApprovalService> _approvals = new();
    private readonly ApprovalsController _controller;

    public ApprovalsControllerTests()
    {
        _approvals
            .Setup(instance => instance.RecordApprovalAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ApprovalRecord(
                "approval-1", Tenants.A, ActionNames.MarkVendorApproved, Subjects.VendorX,
                "dave", "reviewed", DateTimeOffset.UnixEpoch));

        _approvals
            .Setup(instance => instance.GetForTenantAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<ApprovalRecord>());

        _controller = new ApprovalsController(_approvals.Object);
    }

    private static RecordApprovalRequest Body() => new()
    {
        Action = ActionNames.MarkVendorApproved,
        SubjectId = Subjects.VendorX,
        Justification = "Reviewed the gaps.",
    };

    [Fact]
    public async Task Records_an_approval_using_the_callers_claims()
    {
        _controller.AsUser(Tenants.A, "dave", Roles.Approver);

        var response = await _controller.Record(Body(), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(response.Result);

        // Tenant, approver and role all come from the token — the body carries only what is
        // being approved.
        _approvals.Verify(
            instance => instance.RecordApprovalAsync(
                Tenants.A,
                "dave",
                Roles.Approver,
                ActionNames.MarkVendorApproved,
                Subjects.VendorX,
                "Reviewed the gaps.",
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// The approval request contract has no approver field: you are the approver you authenticated
    /// as, so nobody can record an approval in someone else's name.
    /// </summary>
    [Fact]
    public void The_approval_request_contract_cannot_name_a_different_approver()
    {
        var propertyNames = typeof(RecordApprovalRequest)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();

        Assert.Equal(
            new[] { "Action", "Justification", "SubjectId" },
            propertyNames.OrderBy(name => name).ToArray());
    }

    [Fact]
    public async Task Lists_approvals_for_the_callers_tenant_only()
    {
        _controller.AsUser(Tenants.B, "erin", Roles.Approver);

        await _controller.List(CancellationToken.None);

        _approvals.Verify(
            instance => instance.GetForTenantAsync(Tenants.B, It.IsAny<CancellationToken>()),
            Times.Once);

        _approvals.Verify(
            instance => instance.GetForTenantAsync(
                It.Is<string>(tenantId => tenantId != Tenants.B), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Refuses_a_principal_naming_an_unknown_tenant()
    {
        _controller.AsUser(tenantId: "tenant-does-not-exist", role: Roles.Approver);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Record(Body(), CancellationToken.None));

        _approvals.Verify(
            instance => instance.RecordApprovalAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    /// <summary>
    /// The HTTP layer restricts this to approvers via <c>[Authorize(Roles = …)]</c>, but the role
    /// is also passed to the service, which re-checks it. Defence in depth that survives a routing
    /// or attribute mistake.
    /// </summary>
    [Fact]
    public async Task Passes_the_callers_role_to_the_service_for_re_checking()
    {
        _controller.AsUser(Tenants.A, "alice", Roles.Analyst);

        await _controller.Record(Body(), CancellationToken.None);

        _approvals.Verify(
            instance => instance.RecordApprovalAsync(
                It.IsAny<string>(), It.IsAny<string>(), Roles.Analyst, It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }
}

public sealed class AuditControllerTests
{
    private readonly Mock<IAuditService> _audit = new();
    private readonly AuditController _controller;

    public AuditControllerTests()
    {
        _audit
            .Setup(instance => instance.GetForTenantAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<AuditEvent>());

        _controller = new AuditController(_audit.Object);
    }

    [Fact]
    public async Task Reads_the_trail_for_the_callers_tenant_only()
    {
        _controller.AsUser(Tenants.B, "carol", Roles.Analyst);

        var response = await _controller.Get(CancellationToken.None);

        Assert.IsType<OkObjectResult>(response.Result);

        _audit.Verify(
            instance => instance.GetForTenantAsync(Tenants.B, It.IsAny<CancellationToken>()),
            Times.Once);

        _audit.Verify(
            instance => instance.GetForTenantAsync(
                It.Is<string>(tenantId => tenantId != Tenants.B), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Refuses_a_principal_with_no_tenant_claim()
    {
        _controller.AsUser(tenantId: null);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Get(CancellationToken.None));

        _audit.Verify(
            instance => instance.GetForTenantAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}

public sealed class EvidenceControllerTests
{
    private readonly Mock<IEvidenceService> _evidence = new();
    private readonly EvidenceController _controller;

    public EvidenceControllerTests()
    {
        _evidence
            .Setup(instance => instance.SearchEvidenceAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[]
            {
                new EvidenceSnippet(
                    "evidence-a-666", Subjects.VendorX, "Attestation", "attestation",
                    "snippet", Array.Empty<string>(), null,
                    IsTrusted: false, new[] { "ignore-previous-instructions" }),
            });

        _controller = new EvidenceController(_evidence.Object);
    }

    [Fact]
    public async Task Searches_within_the_callers_tenant_only()
    {
        _controller.AsUser(Tenants.A, "alice", Roles.Analyst);

        await _controller.Get(Subjects.VendorX, "payment data", CancellationToken.None);

        _evidence.Verify(
            instance => instance.SearchEvidenceAsync(
                Tenants.A, Subjects.VendorX, "payment data", It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Treats_a_missing_query_as_empty_rather_than_failing()
    {
        _controller.AsUser();

        await _controller.Get(Subjects.VendorX, null, CancellationToken.None);

        _evidence.Verify(
            instance => instance.SearchEvidenceAsync(
                Tenants.A, Subjects.VendorX, string.Empty, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// The endpoint exists so quarantining is observable from outside the engine, which means the
    /// trust verdict has to survive the mapping to the response DTO.
    /// </summary>
    [Fact]
    public async Task Surfaces_the_trust_verdict_and_matched_patterns()
    {
        _controller.AsUser();

        var response = await _controller.Get(Subjects.VendorX, "q", CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(response.Result);
        var body = Assert.IsType<EvidenceSnippetResponse[]>(ok.Value);

        var snippet = Assert.Single(body);

        Assert.False(snippet.IsTrusted);
        Assert.Contains("ignore-previous-instructions", snippet.InjectionPatterns);
    }

    [Fact]
    public async Task Refuses_a_principal_naming_an_unknown_role()
    {
        _controller.AsUser(role: "superuser");

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Get(Subjects.VendorX, "q", CancellationToken.None));
    }
}
