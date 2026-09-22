namespace RegulatedAi.Core.Data;

/// <summary>
/// Builds the tenant-scoped cache keys used by every store.
/// </summary>
/// <remarks>
/// <para>
/// Tenant isolation in this solution is <b>structural</b>: every store method takes a tenant id,
/// every key embeds it, and no method exists that returns data across tenants. There is nothing
/// to remember to filter, which means there is nothing to forget.
/// </para>
/// <para>
/// <see cref="Normalize"/> rejects a tenant id containing the key separator. Tenant ids here come
/// from tokens this service issues, so the risk is low today — but a store keyed by string
/// concatenation is a key-injection target the moment tenant ids come from anywhere else, and the
/// guard costs nothing now.
/// </para>
/// </remarks>
internal static class TenantKey
{
    private const string Separator = "::";

    internal static string Normalize(string tenantId)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException("A tenant id is required for every store access.", nameof(tenantId));
        }

        if (tenantId.Contains(Separator, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"Tenant id must not contain the key separator '{Separator}'.", nameof(tenantId));
        }

        return tenantId.Trim().ToLowerInvariant();
    }

    internal static string For(string partition, string tenantId) =>
        string.Concat(partition, Separator, Normalize(tenantId));

    internal const string EvidencePartition = "evidence";
    internal const string ApprovalsPartition = "approvals";
    internal const string AuditPartition = "audit";
    internal const string UsersKey = "users";
}
