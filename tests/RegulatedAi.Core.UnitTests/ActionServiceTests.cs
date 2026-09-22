using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using RegulatedAi.Core.Actions;
using RegulatedAi.Core.Actions.Handlers;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Security;
using RegulatedAi.Core.UnitTests.TestSupport;

namespace RegulatedAi.Core.UnitTests;

public sealed class ActionServiceTests
{
    private const string TenantA = "tenant-a";
    private const string Action = "markVendorApproved";
    private const string Subject = "vendor-x";

    private static ActionExecutionContext Context(
        string action = Action,
        string role = Roles.Approver,
        ApprovalRecord? approval = null) =>
        new(TenantA, "bob", role, action, Subject, RiskLevel.High, approval, "corr-1");

    private static ApprovalRecord Approval() =>
        new("approval-1", TenantA, Action, Subject, "dave", "reviewed", Mocked.Now);

    // ---------------------------------------------------------------------------------------
    // Registry
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Finds_a_registered_handler_by_name()
    {
        var handler = Mocked.ActionHandler("doThing", Roles.Analyst);
        var service = new ActionService(new[] { handler.Object });

        Assert.Same(handler.Object, service.FindHandler("doThing"));
    }

    [Fact]
    public void Matches_action_names_case_insensitively()
    {
        var service = new ActionService(new[] { Mocked.ActionHandler("doThing", Roles.Analyst).Object });

        Assert.NotNull(service.FindHandler("DOTHING"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("nobodyRegisteredThis")]
    public void Returns_no_handler_for_an_unknown_or_absent_action(string? action) =>
        Assert.Null(new ActionService(Array.Empty<IActionHandler>()).FindHandler(action));

    [Fact]
    public void Lists_its_registered_actions()
    {
        var service = new ActionService(new[]
        {
            Mocked.ActionHandler("a", Roles.Analyst).Object,
            Mocked.ActionHandler("b", Roles.Approver).Object,
        });

        Assert.Equal(new[] { "a", "b" }, service.RegisteredActions.OrderBy(name => name).ToArray());
    }

    /// <summary>
    /// Two handlers for one name would make which gate applies depend on registration order.
    /// Refusing at construction turns a subtle request-time ambiguity into a startup failure.
    /// </summary>
    [Fact]
    public void Refuses_duplicate_handler_registrations()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => new ActionService(new[]
        {
            Mocked.ActionHandler("doThing", Roles.Analyst).Object,
            Mocked.ActionHandler("doThing", Roles.Approver).Object,
        }));

        Assert.Contains("doThing", exception.Message);
    }

    // ---------------------------------------------------------------------------------------
    // Execution and gates
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Executes_a_registered_action()
    {
        var handler = Mocked.ActionHandler();
        var service = new ActionService(new[] { handler.Object });

        var outcome = await service.ExecuteAsync(Context());

        Assert.Equal(ActionStatus.Executed, outcome.Status);
        handler.Verify(
            instance => instance.ExecuteAsync(
                It.IsAny<ActionExecutionContext>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Fails_closed_on_an_unknown_action()
    {
        var service = new ActionService(Array.Empty<IActionHandler>());

        var outcome = await service.ExecuteAsync(Context(action: "nobodyRegisteredThis"));

        Assert.Equal(ActionStatus.UnsupportedAction, outcome.Status);
    }

    /// <summary>
    /// Defence in depth. The orchestrator checks the role too, but the check belongs with the
    /// thing it protects, so a caller reaching this service directly does not bypass it.
    /// </summary>
    [Fact]
    public async Task Enforces_the_role_gate_independently_of_the_orchestrator()
    {
        var handler = Mocked.ActionHandler(minimumRole: Roles.Approver);
        var service = new ActionService(new[] { handler.Object });

        var outcome = await service.ExecuteAsync(Context(role: Roles.Analyst));

        Assert.Equal(ActionStatus.DeniedInsufficientRole, outcome.Status);
        handler.Verify(
            instance => instance.ExecuteAsync(
                It.IsAny<ActionExecutionContext>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Denies_an_unknown_role()
    {
        var handler = Mocked.ActionHandler(minimumRole: Roles.Analyst);
        var service = new ActionService(new[] { handler.Object });

        var outcome = await service.ExecuteAsync(Context(role: "superuser"));

        Assert.Equal(ActionStatus.DeniedInsufficientRole, outcome.Status);
        handler.Verify(
            instance => instance.ExecuteAsync(
                It.IsAny<ActionExecutionContext>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Allows_a_role_above_the_minimum()
    {
        var handler = Mocked.ActionHandler(minimumRole: Roles.Analyst);
        var service = new ActionService(new[] { handler.Object });

        var outcome = await service.ExecuteAsync(Context(role: Roles.Approver));

        Assert.Equal(ActionStatus.Executed, outcome.Status);
    }

    [Fact]
    public async Task Passes_the_verified_approval_through_to_the_handler()
    {
        var handler = Mocked.ActionHandler();
        var service = new ActionService(new[] { handler.Object });

        await service.ExecuteAsync(Context(approval: Approval()));

        handler.Verify(
            instance => instance.ExecuteAsync(
                It.Is<ActionExecutionContext>(context => context.Approval!.ApprovedBy == "dave"),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Returns_whatever_outcome_the_handler_reports()
    {
        var handler = Mocked.ActionHandler(outcome: ActionOutcome.Executed("did the thing"));
        var service = new ActionService(new[] { handler.Object });

        Assert.Equal("did the thing", (await service.ExecuteAsync(Context())).Detail);
    }

    // ---------------------------------------------------------------------------------------
    // The real handler
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void MarkVendorApproved_declares_the_expected_gates()
    {
        var handler = new MarkVendorApprovedHandler(NullLogger<MarkVendorApprovedHandler>.Instance);

        Assert.Equal(Action, handler.ActionName);
        Assert.Equal(Roles.Approver, handler.MinimumRole);

        // False: approval is demanded by the high-risk rule, which for a payment-data vendor with
        // any evidence gap always fires. A deployment wanting a human on *every* vendor approval
        // flips this and nothing else changes.
        Assert.False(handler.AlwaysRequiresApproval);
    }

    [Fact]
    public async Task MarkVendorApproved_names_the_subject_and_the_approval_it_acted_under()
    {
        var handler = new MarkVendorApprovedHandler(NullLogger<MarkVendorApprovedHandler>.Instance);

        var outcome = await handler.ExecuteAsync(Context(approval: Approval()));

        Assert.Equal(ActionStatus.Executed, outcome.Status);
        Assert.Contains(Subject, outcome.Detail);
        Assert.Contains("approval-1", outcome.Detail);
        Assert.Contains("dave", outcome.Detail);
    }

    [Fact]
    public async Task MarkVendorApproved_says_so_when_no_approval_was_required()
    {
        var handler = new MarkVendorApprovedHandler(NullLogger<MarkVendorApprovedHandler>.Instance);

        var outcome = await handler.ExecuteAsync(
            new ActionExecutionContext(
                TenantA, "erin", Roles.Approver, Action, "vendor-y",
                RiskLevel.Low, null, "corr-1"));

        Assert.Contains("no approval required", outcome.Detail);
    }

    [Fact]
    public async Task MarkVendorApproved_honours_cancellation()
    {
        var handler = new MarkVendorApprovedHandler(NullLogger<MarkVendorApprovedHandler>.Instance);

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => handler.ExecuteAsync(Context(), cancelled.Token));
    }
}
