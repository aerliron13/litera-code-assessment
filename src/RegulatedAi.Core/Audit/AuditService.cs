using Microsoft.Extensions.Logging;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;

namespace RegulatedAi.Core.Audit;

/// <inheritdoc cref="IAuditService"/>
public sealed class AuditService : IAuditService
{
    private readonly IAuditStore _store;
    private readonly IClock _clock;
    private readonly ILogger<AuditService> _logger;

    public AuditService(IAuditStore store, IClock clock, ILogger<AuditService> logger)
    {
        _store = store;
        _clock = clock;
        _logger = logger;
    }

    public Task<AuditEvent> WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(auditEvent.TenantId))
        {
            throw new ArgumentException("An audit event must be attributed to a tenant.", nameof(auditEvent));
        }

        if (string.IsNullOrWhiteSpace(auditEvent.EventType))
        {
            throw new ArgumentException("An audit event must have a type.", nameof(auditEvent));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var stamped = auditEvent with
        {
            EventId = Guid.NewGuid().ToString("n"),
            OccurredAtUtc = _clock.UtcNow,
        };

        _store.Append(stamped);

        // Structured fields only, and only identifiers and rule names. Evidence text never reaches
        // a log sink from here: see the note on AuditEvent.Detail.
        _logger.LogInformation(
            "Audit {EventType} tenant={TenantId} user={UserId} role={Role} action={Action} "
            + "subject={SubjectId} risk={RiskLevel} status={ActionStatus} correlationId={CorrelationId} "
            + "eventId={EventId}",
            stamped.EventType,
            stamped.TenantId,
            stamped.UserId,
            stamped.Role,
            stamped.Action,
            stamped.SubjectId,
            stamped.RiskLevel,
            stamped.ActionStatus,
            stamped.CorrelationId,
            stamped.EventId);

        return Task.FromResult(stamped);
    }

    public Task<IReadOnlyList<AuditEvent>> GetForTenantAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException("A tenant id is required.", nameof(tenantId));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var events = _store.GetForTenant(tenantId)
            .OrderBy(auditEvent => auditEvent.OccurredAtUtc)
            .ToArray();

        return Task.FromResult<IReadOnlyList<AuditEvent>>(events);
    }
}
