using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;
using RegulatedAi.Core.UnitTests.TestSupport;

namespace RegulatedAi.Core.UnitTests;

public sealed class AuditServiceTests
{
    private const string TenantA = "tenant-a";
    private const string TenantB = "tenant-b";

    private readonly Mock<IClock> _clock = Mocked.Clock();
    private readonly Mock<IAuditStore> _store = Mocked.AuditStore();
    private readonly AuditService _service;

    public AuditServiceTests() =>
        _service = new AuditService(_store.Object, _clock.Object, NullLogger<AuditService>.Instance);

    private static AuditEvent Event(
        string tenantId = TenantA,
        string eventType = AuditEventTypes.WorkflowRun,
        string userId = "alice") =>
        new()
        {
            TenantId = tenantId,
            UserId = userId,
            Role = Roles.Analyst,
            EventType = eventType,
            CorrelationId = "corr-1",
        };

    [Fact]
    public async Task Stamps_an_event_id_and_timestamp()
    {
        var written = await _service.WriteAsync(Event());

        Assert.NotEmpty(written.EventId);
        Assert.Equal(Mocked.Now, written.OccurredAtUtc);
    }

    /// <summary>
    /// A caller must not be able to choose an event's identity or claim it happened at a
    /// convenient time.
    /// </summary>
    [Fact]
    public async Task Overwrites_a_caller_supplied_id_and_timestamp()
    {
        var forged = Event() with
        {
            EventId = "forged-id",
            OccurredAtUtc = new DateTimeOffset(1999, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };

        var written = await _service.WriteAsync(forged);

        Assert.NotEqual("forged-id", written.EventId);
        Assert.Equal(Mocked.Now, written.OccurredAtUtc);
    }

    [Fact]
    public async Task Appends_the_stamped_event_not_the_original()
    {
        await _service.WriteAsync(Event() with { EventId = "forged-id" });

        _store.Verify(
            instance => instance.Append(It.Is<AuditEvent>(item => item.EventId != "forged-id")),
            Times.Once);
    }

    [Fact]
    public async Task Assigns_a_distinct_id_to_every_event()
    {
        await _service.WriteAsync(Event());
        await _service.WriteAsync(Event());

        var events = await _service.GetForTenantAsync(TenantA);

        Assert.Equal(2, events.Select(item => item.EventId).Distinct().Count());
    }

    [Fact]
    public async Task Reads_are_tenant_scoped()
    {
        await _service.WriteAsync(Event(TenantA, userId: "alice"));
        await _service.WriteAsync(Event(TenantB, userId: "carol"));

        Assert.Equal("alice", Assert.Single(await _service.GetForTenantAsync(TenantA)).UserId);
        Assert.Equal("carol", Assert.Single(await _service.GetForTenantAsync(TenantB)).UserId);
    }

    [Fact]
    public async Task Reads_only_the_requested_tenant_partition()
    {
        await _service.GetForTenantAsync(TenantA);

        _store.Verify(instance => instance.GetForTenant(TenantA), Times.Once);
        _store.Verify(
            instance => instance.GetForTenant(It.Is<string>(id => id != TenantA)), Times.Never);
    }

    [Fact]
    public async Task Preserves_write_order_when_timestamps_are_identical()
    {
        await _service.WriteAsync(Event(eventType: AuditEventTypes.EvidenceQuarantined));
        await _service.WriteAsync(Event(eventType: AuditEventTypes.ActionBlockedPendingApproval));
        await _service.WriteAsync(Event(eventType: AuditEventTypes.WorkflowRun));

        var events = await _service.GetForTenantAsync(TenantA);

        // The clock does not move here, so ordering falls back to insertion order. A trail that
        // reorders itself under a coarse clock is hard to read during an incident.
        Assert.Equal(
            new[]
            {
                AuditEventTypes.EvidenceQuarantined,
                AuditEventTypes.ActionBlockedPendingApproval,
                AuditEventTypes.WorkflowRun,
            },
            events.Select(item => item.EventType).ToArray());
    }

    [Fact]
    public async Task Orders_by_time_when_the_clock_advances()
    {
        await _service.WriteAsync(Event(eventType: "later"));

        _clock.SetupGet(instance => instance.UtcNow).Returns(Mocked.Now.AddMinutes(-5));
        await _service.WriteAsync(Event(eventType: "earlier"));

        var events = await _service.GetForTenantAsync(TenantA);

        Assert.Equal("earlier", events[0].EventType);
    }

    [Fact]
    public async Task Requires_a_tenant_on_every_event() =>
        await Assert.ThrowsAsync<ArgumentException>(() => _service.WriteAsync(Event(tenantId: "   ")));

    [Fact]
    public async Task Requires_an_event_type() =>
        await Assert.ThrowsAsync<ArgumentException>(() => _service.WriteAsync(Event(eventType: "   ")));

    [Fact]
    public async Task Does_not_store_an_invalid_event()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _service.WriteAsync(Event(tenantId: " ")));

        _store.Verify(instance => instance.Append(It.IsAny<AuditEvent>()), Times.Never);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Requires_a_tenant_id_to_read(string? tenantId) =>
        await Assert.ThrowsAsync<ArgumentException>(() => _service.GetForTenantAsync(tenantId!));

    [Fact]
    public async Task Returns_an_empty_trail_for_a_tenant_with_no_events() =>
        Assert.Empty(await _service.GetForTenantAsync("tenant-with-nothing"));

    // ---------------------------------------------------------------------------------------
    // Event type mapping
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ActionStatus.Executed, AuditEventTypes.ActionExecuted)]
    [InlineData(ActionStatus.BlockedPendingApproval, AuditEventTypes.ActionBlockedPendingApproval)]
    [InlineData(ActionStatus.DeniedInsufficientRole, AuditEventTypes.ActionDeniedInsufficientRole)]
    [InlineData(ActionStatus.UnsupportedAction, AuditEventTypes.ActionUnsupported)]
    public void Maps_every_attempt_outcome_to_an_event_type(ActionStatus status, string expected)
    {
        var eventType = AuditEventTypes.ForActionStatus(status);

        Assert.Equal(expected, eventType);
        Assert.StartsWith(AuditEventTypes.ActionPrefix, eventType);
    }

    [Fact]
    public void Refuses_to_map_a_non_attempt_to_an_action_event_type() =>
        Assert.Throws<ArgumentOutOfRangeException>(
            () => AuditEventTypes.ForActionStatus(ActionStatus.NotRequested));
}
