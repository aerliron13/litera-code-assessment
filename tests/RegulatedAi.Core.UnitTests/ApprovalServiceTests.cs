using Moq;
using RegulatedAi.Core.Approvals;
using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Security;
using RegulatedAi.Core.UnitTests.TestSupport;

namespace RegulatedAi.Core.UnitTests;

/// <summary>
/// The approval gate. This is the exercise's central security control, so it is probed from every
/// angle: no record, wrong tenant, wrong subject, wrong action, wrong approver, and self-approval.
/// </summary>
public sealed class ApprovalServiceTests
{
    private const string TenantA = "tenant-a";
    private const string TenantB = "tenant-b";
    private const string Action = "markVendorApproved";
    private const string Subject = "vendor-x";

    private readonly Mock<IAuditService> _audit;
    private readonly List<AuditEvent> _written;
    private readonly ApprovalService _service;

    public ApprovalServiceTests()
    {
        (_audit, _written) = Mocked.AuditService();

        _service = new ApprovalService(
            Mocked.ApprovalStore().Object,
            _audit.Object,
            Mocked.Clock().Object);
    }

    private IEnumerable<string> WrittenEventTypes => _written.Select(item => item.EventType);

    private Task<ApprovalRecord> RecordAsync(
        string approver = "dave",
        string role = Roles.Approver,
        string tenantId = TenantA,
        string action = Action,
        string subjectId = Subject) =>
        _service.RecordApprovalAsync(tenantId, approver, role, action, subjectId, "reviewed the gaps");

    // ---------------------------------------------------------------------------------------
    // Recording
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Records_an_approval_and_audits_it()
    {
        var record = await RecordAsync();

        Assert.Equal(TenantA, record.TenantId);
        Assert.Equal("dave", record.ApprovedBy);
        Assert.Equal(Mocked.Now, record.ApprovedAtUtc);
        Assert.NotEmpty(record.ApprovalId);

        // An approval that leaves no trace is not one anyone can review afterwards, so the audit
        // write happens inside this call rather than being left to the caller.
        Assert.Contains(AuditEventTypes.ApprovalRecorded, WrittenEventTypes);
    }

    [Fact]
    public async Task Refuses_to_record_an_approval_from_an_insufficient_role()
    {
        await Assert.ThrowsAsync<InvalidWorkflowRequestException>(
            () => RecordAsync(approver: "alice", role: Roles.Analyst));

        // A refused attempt to grant approval is exactly what a compliance reviewer wants to see,
        // so it must not fail silently.
        Assert.Contains(AuditEventTypes.ApprovalRejected, WrittenEventTypes);
    }

    [Fact]
    public async Task Refuses_to_record_an_approval_from_an_unknown_role() =>
        await Assert.ThrowsAsync<InvalidWorkflowRequestException>(() => RecordAsync(role: "superuser"));

    [Fact]
    public async Task A_refused_approval_is_not_stored()
    {
        var store = Mocked.ApprovalStore();
        var service = new ApprovalService(store.Object, _audit.Object, Mocked.Clock().Object);

        await Assert.ThrowsAsync<InvalidWorkflowRequestException>(
            () => service.RecordApprovalAsync(
                TenantA, "alice", Roles.Analyst, Action, Subject, "let me in"));

        store.Verify(instance => instance.Append(It.IsAny<ApprovalRecord>()), Times.Never);
    }

    [Fact]
    public async Task Supplies_a_placeholder_when_no_justification_is_given()
    {
        var record = await _service.RecordApprovalAsync(
            TenantA, "dave", Roles.Approver, Action, Subject, "   ");

        Assert.False(string.IsNullOrWhiteSpace(record.Justification));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Requires_an_action(string? action) =>
        await Assert.ThrowsAsync<ArgumentException>(() => RecordAsync(action: action!));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Requires_a_subject(string? subjectId) =>
        await Assert.ThrowsAsync<ArgumentException>(() => RecordAsync(subjectId: subjectId!));

    // ---------------------------------------------------------------------------------------
    // Verification
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Verifies_a_recorded_approval_referenced_by_a_different_user()
    {
        await RecordAsync(approver: "dave");

        var decision = await _service.VerifyApprovalAsync(TenantA, "bob", Action, Subject, "dave");

        Assert.True(decision.IsApproved);
        Assert.Equal("dave", decision.Record!.ApprovedBy);
    }

    /// <summary>
    /// The design decision this service exists for: a name in a request is a reference, not an
    /// authorization. With no record behind it, the action stays blocked.
    /// </summary>
    [Fact]
    public async Task Rejects_an_approvedBy_that_has_no_recorded_approval()
    {
        var decision = await _service.VerifyApprovalAsync(TenantA, "bob", Action, Subject, "dave");

        Assert.False(decision.IsApproved);
        Assert.Contains("No approval record found", decision.Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Rejects_a_request_with_no_approver_referenced(string? approvedBy)
    {
        await RecordAsync(approver: "dave");

        var decision = await _service.VerifyApprovalAsync(TenantA, "bob", Action, Subject, approvedBy);

        Assert.False(decision.IsApproved);
    }

    [Fact]
    public async Task Rejects_self_approval_even_when_the_record_is_genuine()
    {
        // dave really is an approver and really did record this approval...
        await RecordAsync(approver: "dave");

        // ...but dave cannot also be the one requesting the action.
        var decision = await _service.VerifyApprovalAsync(TenantA, "dave", Action, Subject, "dave");

        Assert.False(decision.IsApproved);
        Assert.Contains("Separation of duties", decision.Reason);
    }

    [Fact]
    public async Task Rejects_self_approval_regardless_of_casing()
    {
        await RecordAsync(approver: "dave");

        var decision = await _service.VerifyApprovalAsync(TenantA, "DAVE", Action, Subject, "dave");

        Assert.False(decision.IsApproved);
        Assert.Contains("Separation of duties", decision.Reason);
    }

    // ---------------------------------------------------------------------------------------
    // Scope: one approval unlocks exactly one tenant, action and subject
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_approval_in_another_tenant_does_not_authorise_this_one()
    {
        await RecordAsync(approver: "erin", tenantId: TenantB);

        var decision = await _service.VerifyApprovalAsync(TenantA, "bob", Action, Subject, "erin");

        Assert.False(decision.IsApproved);
    }

    [Fact]
    public async Task An_approval_for_another_subject_does_not_authorise_this_one()
    {
        await RecordAsync(approver: "dave", subjectId: "vendor-other");

        var decision = await _service.VerifyApprovalAsync(TenantA, "bob", Action, Subject, "dave");

        Assert.False(decision.IsApproved);
    }

    [Fact]
    public async Task An_approval_for_another_action_does_not_authorise_this_one()
    {
        await RecordAsync(approver: "dave", action: "someOtherAction");

        var decision = await _service.VerifyApprovalAsync(TenantA, "bob", Action, Subject, "dave");

        Assert.False(decision.IsApproved);
    }

    [Fact]
    public async Task An_approval_recorded_by_someone_else_does_not_satisfy_a_different_reference()
    {
        await RecordAsync(approver: "dave");

        // The record exists, but not from the referenced approver.
        var decision = await _service.VerifyApprovalAsync(TenantA, "alice", Action, Subject, "bob");

        Assert.False(decision.IsApproved);
    }

    /// <summary>
    /// The lookup goes through the tenant-scoped read, so another tenant's record is never even a
    /// candidate rather than being fetched and filtered.
    /// </summary>
    [Fact]
    public async Task Verification_reads_only_the_callers_tenant_partition()
    {
        var store = Mocked.ApprovalStore();
        var service = new ApprovalService(store.Object, _audit.Object, Mocked.Clock().Object);

        await service.VerifyApprovalAsync(TenantA, "bob", Action, Subject, "dave");

        store.Verify(instance => instance.GetForTenant(TenantA), Times.Once);
        store.Verify(
            instance => instance.GetForTenant(It.Is<string>(id => id != TenantA)), Times.Never);
    }

    [Fact]
    public async Task Verification_is_case_insensitive_on_action_and_subject()
    {
        await RecordAsync(approver: "dave");

        var decision = await _service.VerifyApprovalAsync(
            TenantA, "bob", Action.ToUpperInvariant(), Subject.ToUpperInvariant(), "DAVE");

        Assert.True(decision.IsApproved);
    }

    // ---------------------------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Reads_are_tenant_scoped()
    {
        await RecordAsync(approver: "dave", tenantId: TenantA);
        await RecordAsync(approver: "erin", tenantId: TenantB);

        var tenantA = await _service.GetForTenantAsync(TenantA);

        Assert.Equal("dave", Assert.Single(tenantA).ApprovedBy);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Requires_a_tenant_id_to_read(string? tenantId) =>
        await Assert.ThrowsAsync<ArgumentException>(() => _service.GetForTenantAsync(tenantId!));
}
