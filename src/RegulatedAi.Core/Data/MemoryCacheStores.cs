using Microsoft.Extensions.Caching.Memory;
using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Data;

/// <summary>
/// Shared plumbing for the <see cref="IMemoryCache"/>-backed stores.
/// </summary>
/// <remarks>
/// <para>
/// <b>A cache is not a database.</b> The brief calls for in-memory storage, and this is that —
/// but the semantics are worth being explicit about, because two of them would be defects in
/// production:
/// </para>
/// <list type="bullet">
/// <item>
/// Entries are written with <see cref="CacheItemPriority.NeverRemove"/> so that memory pressure
/// cannot silently evict an audit trail. A cache that can drop records is not an audit store.
/// </item>
/// <item>
/// Appends take a per-key lock and replace an immutable list, so two concurrent requests cannot
/// lose an event through a read-modify-write race. A naive <c>List.Add</c> under a shared cache
/// entry would.
/// </item>
/// </list>
/// <para>
/// PRODUCTION_NOTES.md covers what this is replaced with: append-only storage for audit, a
/// transactional store for approvals.
/// </para>
/// </remarks>
public abstract class MemoryCacheStore
{
    private static readonly MemoryCacheEntryOptions EntryOptions = new()
    {
        Priority = CacheItemPriority.NeverRemove,
    };

    private readonly object _writeLock = new();

    protected MemoryCacheStore(IMemoryCache cache) => Cache = cache;

    protected IMemoryCache Cache { get; }

    protected IReadOnlyList<T> Read<T>(string key) =>
        Cache.TryGetValue(key, out IReadOnlyList<T>? items) && items is not null
            ? items
            : Array.Empty<T>();

    protected void Write<T>(string key, IReadOnlyList<T> items)
    {
        lock (_writeLock)
        {
            Cache.Set(key, items, EntryOptions);
        }
    }

    /// <summary>Read-modify-write under a lock, so concurrent appends cannot drop records.</summary>
    protected void AppendTo<T>(string key, T item)
    {
        lock (_writeLock)
        {
            var existing = Read<T>(key);
            var updated = new List<T>(existing.Count + 1);
            updated.AddRange(existing);
            updated.Add(item);
            Cache.Set(key, (IReadOnlyList<T>)updated, EntryOptions);
        }
    }
}

public sealed class MemoryCacheEvidenceStore : MemoryCacheStore, IEvidenceStore
{
    public MemoryCacheEvidenceStore(IMemoryCache cache) : base(cache)
    {
    }

    public IReadOnlyList<EvidenceDocument> GetForTenant(string tenantId) =>
        Read<EvidenceDocument>(TenantKey.For(TenantKey.EvidencePartition, tenantId));

    public void Replace(string tenantId, IReadOnlyList<EvidenceDocument> documents)
    {
        var normalized = TenantKey.Normalize(tenantId);

        // Refuse to file a document under a tenant it does not belong to. Seeding is the only
        // writer today, but a store that trusts its caller's key is one bug away from a leak.
        var foreign = documents
            .Where(document => !string.Equals(
                TenantKey.Normalize(document.TenantId), normalized, StringComparison.Ordinal))
            .Select(document => document.DocumentId)
            .ToArray();

        if (foreign.Length > 0)
        {
            throw new ArgumentException(
                $"Documents {string.Join(", ", foreign)} do not belong to tenant '{tenantId}'.",
                nameof(documents));
        }

        Write(TenantKey.For(TenantKey.EvidencePartition, tenantId), documents);
    }
}

public sealed class MemoryCacheApprovalStore : MemoryCacheStore, IApprovalStore
{
    public MemoryCacheApprovalStore(IMemoryCache cache) : base(cache)
    {
    }

    public IReadOnlyList<ApprovalRecord> GetForTenant(string tenantId) =>
        Read<ApprovalRecord>(TenantKey.For(TenantKey.ApprovalsPartition, tenantId));

    public void Append(ApprovalRecord record) =>
        AppendTo(TenantKey.For(TenantKey.ApprovalsPartition, record.TenantId), record);
}

public sealed class MemoryCacheAuditStore : MemoryCacheStore, IAuditStore
{
    public MemoryCacheAuditStore(IMemoryCache cache) : base(cache)
    {
    }

    public IReadOnlyList<AuditEvent> GetForTenant(string tenantId) =>
        Read<AuditEvent>(TenantKey.For(TenantKey.AuditPartition, tenantId));

    public void Append(AuditEvent auditEvent) =>
        AppendTo(TenantKey.For(TenantKey.AuditPartition, auditEvent.TenantId), auditEvent);
}

public sealed class MemoryCacheUserStore : MemoryCacheStore, IUserStore
{
    public MemoryCacheUserStore(IMemoryCache cache) : base(cache)
    {
    }

    public UserAccount? FindByUsername(string username) =>
        string.IsNullOrWhiteSpace(username)
            ? null
            : Read<UserAccount>(TenantKey.UsersKey)
                .FirstOrDefault(user => string.Equals(
                    user.Username, username.Trim(), StringComparison.OrdinalIgnoreCase));

    public void Replace(IReadOnlyList<UserAccount> users) => Write(TenantKey.UsersKey, users);
}
