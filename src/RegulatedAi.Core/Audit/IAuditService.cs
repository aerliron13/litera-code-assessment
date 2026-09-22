using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Audit;

/// <summary>
/// The exercise's <c>writeAuditEvent</c>. Append-only by construction: there is no update and no
/// delete, and reads are tenant-scoped.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Appends an event and returns it as stamped. <see cref="AuditEvent.EventId"/> and
    /// <see cref="AuditEvent.OccurredAtUtc"/> are assigned here and overwrite anything the caller
    /// supplied, so no caller can forge the identity or the timing of a record.
    /// </summary>
    Task<AuditEvent> WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditEvent>> GetForTenantAsync(
        string tenantId,
        CancellationToken cancellationToken = default);
}
