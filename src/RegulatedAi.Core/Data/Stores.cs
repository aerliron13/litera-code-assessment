using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Data;

/// <summary>
/// Tenant-scoped evidence storage. Note that there is no <c>GetAll</c>: the absence of an
/// unscoped read is the isolation guarantee.
/// </summary>
public interface IEvidenceStore
{
    IReadOnlyList<EvidenceDocument> GetForTenant(string tenantId);

    void Replace(string tenantId, IReadOnlyList<EvidenceDocument> documents);
}

/// <summary>Tenant-scoped approval records. Append-only.</summary>
public interface IApprovalStore
{
    IReadOnlyList<ApprovalRecord> GetForTenant(string tenantId);

    void Append(ApprovalRecord record);
}

/// <summary>Tenant-scoped audit trail. Append-only; no update or delete is exposed.</summary>
public interface IAuditStore
{
    IReadOnlyList<AuditEvent> GetForTenant(string tenantId);

    void Append(AuditEvent auditEvent);
}

/// <summary>
/// A user directory, standing in for the identity provider a real deployment would delegate to.
/// </summary>
public interface IUserStore
{
    UserAccount? FindByUsername(string username);

    void Replace(IReadOnlyList<UserAccount> users);
}

/// <summary>
/// A seeded user. <see cref="DevPassword"/> is named to be impossible to mistake for something
/// production-worthy: it is a plaintext value from configuration, compared in fixed time, and it
/// exists only because the brief rules out a real authentication provider.
/// </summary>
public sealed record UserAccount(
    string UserId,
    string Username,
    string DevPassword,
    string TenantId,
    string Role);
