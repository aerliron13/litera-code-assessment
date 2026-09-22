using Microsoft.AspNetCore.Mvc;
using Moq;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Api.Controllers;
using RegulatedAi.Api.UnitTests.TestSupport;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;
using RegulatedAi.Core.Workflow;

namespace RegulatedAi.Api.UnitTests;

/// <summary>
/// The controller that turns an HTTP request into a workflow request.
/// </summary>
/// <remarks>
/// This is the trust boundary for identity, so most of these tests are about one thing: the tenant,
/// user and role handed to the engine come from token claims and from nowhere else.
/// </remarks>
public sealed class WorkflowControllerTests
{
    private readonly Mock<IWorkflowService> _workflow = new();
    private readonly WorkflowController _controller;

    private WorkflowRequest? _captured;

    public WorkflowControllerTests()
    {
        _workflow
            .Setup(instance => instance.RunWorkflowAsync(
                It.IsAny<WorkflowRequest>(), It.IsAny<CancellationToken>()))
            .Callback((WorkflowRequest request, CancellationToken _) => _captured = request)
            .ReturnsAsync(Result());

        _controller = new WorkflowController(_workflow.Object);
    }

    private static WorkflowResult Result() => new()
    {
        RiskLevel = RiskLevel.High,
        Recommendation = "Do not approve yet.",
        Reasons = new[] { "No SOC 2 evidence found." },
        Citations = new[] { new Citation("policy-a-002", "requirement text") },
        MissingEvidence = new[] { "SOC 2 report" },
        RequiresApproval = true,
        ActionStatus = ActionStatus.BlockedPendingApproval,
        ActionDetail = "blocked",
        QuarantinedEvidence = Array.Empty<QuarantinedEvidence>(),
        CorrelationId = Caller.CorrelationId,
    };

    private static RunWorkflowRequest Body(
        string question = "Can we approve Vendor X to process customer payment data?",
        string subjectId = Subjects.VendorX,
        string? requestedAction = ActionNames.MarkVendorApproved,
        string? approvedBy = null) =>
        new()
        {
            Question = question,
            SubjectId = subjectId,
            RequestedAction = requestedAction,
            ApprovedBy = approvedBy,
        };

    // -------------------------------------------------------------------------------------------
    // The trust boundary
    // -------------------------------------------------------------------------------------------

    [Fact]
    public async Task Populates_tenant_user_and_role_from_the_token_claims()
    {
        _controller.AsUser(Tenants.B, "erin", Roles.Approver);

        await _controller.Run(Body(), CancellationToken.None);

        Assert.NotNull(_captured);
        Assert.Equal(Tenants.B, _captured!.TenantId);
        Assert.Equal("erin", _captured.UserId);
        Assert.Equal(Roles.Approver, _captured.Role);
    }

    /// <summary>
    /// The structural argument for tenant isolation: the request contract has no tenant, user or
    /// role field, so a caller has no way to express another tenant's identity. If this ever
    /// stops being true, this test is where it shows up.
    /// </summary>
    [Fact]
    public void The_request_contract_has_no_identity_fields()
    {
        var propertyNames = typeof(RunWorkflowRequest)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();

        Assert.Equal(
            new[] { "ApprovedBy", "Question", "RequestedAction", "SubjectId" },
            propertyNames.OrderBy(name => name).ToArray());

        Assert.DoesNotContain("TenantId", propertyNames);
        Assert.DoesNotContain("UserId", propertyNames);
        Assert.DoesNotContain("Role", propertyNames);
    }

    [Fact]
    public async Task Passes_the_question_subject_and_approval_reference_from_the_body()
    {
        _controller.AsUser(Tenants.A, "bob", Roles.Approver);

        await _controller.Run(
            Body(question: "Is vendor-x safe?", subjectId: "vendor-x", approvedBy: "dave"),
            CancellationToken.None);

        Assert.Equal("Is vendor-x safe?", _captured!.Question);
        Assert.Equal("vendor-x", _captured.SubjectId);
        Assert.Equal(ActionNames.MarkVendorApproved, _captured.RequestedAction);
        Assert.Equal("dave", _captured.ApprovedBy);
    }

    [Fact]
    public async Task Supplies_a_correlation_id_so_the_run_is_traceable()
    {
        _controller.AsUser();

        await _controller.Run(Body(), CancellationToken.None);

        Assert.Equal(Caller.CorrelationId, _captured!.CorrelationId);
    }

    [Fact]
    public async Task Passes_an_advisory_request_through_with_no_action()
    {
        _controller.AsUser();

        await _controller.Run(Body(requestedAction: null), CancellationToken.None);

        Assert.Null(_captured!.RequestedAction);
    }

    // -------------------------------------------------------------------------------------------
    // Unusable claims
    // -------------------------------------------------------------------------------------------

    [Fact]
    public async Task Refuses_a_principal_with_no_tenant_claim()
    {
        _controller.AsUser(tenantId: null);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Run(Body(), CancellationToken.None));

        AssertEngineWasNotInvoked();
    }

    [Fact]
    public async Task Refuses_a_principal_naming_an_unknown_tenant()
    {
        _controller.AsUser(tenantId: "tenant-does-not-exist");

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Run(Body(), CancellationToken.None));

        AssertEngineWasNotInvoked();
    }

    [Fact]
    public async Task Refuses_a_principal_with_no_subject_claim()
    {
        _controller.AsUser(userId: null);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Run(Body(), CancellationToken.None));

        AssertEngineWasNotInvoked();
    }

    [Fact]
    public async Task Refuses_a_principal_naming_an_unknown_role()
    {
        _controller.AsUser(role: "superuser");

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Run(Body(), CancellationToken.None));

        AssertEngineWasNotInvoked();
    }

    [Fact]
    public async Task Refuses_an_anonymous_principal()
    {
        _controller.As(Caller.Anonymous());

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _controller.Run(Body(), CancellationToken.None));

        AssertEngineWasNotInvoked();
    }

    // -------------------------------------------------------------------------------------------
    // Response and plumbing
    // -------------------------------------------------------------------------------------------

    [Fact]
    public async Task Returns_the_engines_result_unmodified()
    {
        _controller.AsUser();

        var response = await _controller.Run(Body(), CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(response.Result);
        var body = Assert.IsType<WorkflowResult>(ok.Value);

        Assert.Equal(RiskLevel.High, body.RiskLevel);
        Assert.Equal(ActionStatus.BlockedPendingApproval, body.ActionStatus);
        Assert.True(body.RequiresApproval);
    }

    [Fact]
    public async Task Forwards_the_cancellation_token()
    {
        _controller.AsUser();

        using var source = new CancellationTokenSource();

        await _controller.Run(Body(), source.Token);

        _workflow.Verify(
            instance => instance.RunWorkflowAsync(It.IsAny<WorkflowRequest>(), source.Token),
            Times.Once);
    }

    [Fact]
    public async Task Lets_an_engine_rejection_propagate_to_the_error_middleware()
    {
        _workflow
            .Setup(instance => instance.RunWorkflowAsync(
                It.IsAny<WorkflowRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidWorkflowRequestException("bad request"));

        _controller.AsUser();

        // The controller deliberately does not catch: exception-to-status mapping lives in one
        // place so it cannot drift between controllers.
        await Assert.ThrowsAsync<InvalidWorkflowRequestException>(
            () => _controller.Run(Body(), CancellationToken.None));
    }

    private void AssertEngineWasNotInvoked() =>
        _workflow.Verify(
            instance => instance.RunWorkflowAsync(
                It.IsAny<WorkflowRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
}
