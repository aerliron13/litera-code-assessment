namespace RegulatedAi.Core.Security;

/// <summary>
/// The role model. Kept to two ranked roles because the brief explicitly says a simple role field
/// is enough; the ranking, not the names, is the part worth defending.
/// </summary>
/// <remarks>
/// A real deployment would not rank roles at all — it would grant discrete permissions
/// ("vendor.approve.execute") and check for the permission rather than for a role at or above a
/// threshold, because ranking makes every new role a change to the ordering. The rank here is a
/// deliberate simplification, isolated behind <see cref="Satisfies"/> so it is the only thing
/// that would need replacing.
/// </remarks>
public static class Roles
{
    /// <summary>May run workflows and read their tenant's audit trail. May not execute risky actions.</summary>
    public const string Analyst = "analyst";

    /// <summary>May additionally record approvals and execute approved risky actions.</summary>
    public const string Approver = "approver";

    private static readonly IReadOnlyDictionary<string, int> Ranks =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            [Analyst] = 10,
            [Approver] = 20,
        };

    public static IReadOnlyCollection<string> All { get; } = new[] { Analyst, Approver };

    public static bool IsKnown(string? role) => TryRank(role, out _);

    /// <summary>
    /// True when <paramref name="role"/> meets or exceeds <paramref name="minimumRole"/>.
    /// Fails closed: an unrecognised role satisfies nothing, and an unrecognised requirement is
    /// satisfied by nobody.
    /// </summary>
    public static bool Satisfies(string? role, string minimumRole) =>
        TryRank(role, out var actual)
        && TryRank(minimumRole, out var required)
        && actual >= required;

    /// <summary>
    /// Resolves a role name to its rank, trimming and ignoring case.
    /// </summary>
    /// <remarks>
    /// Normalisation lives here so that role names and tenant ids are treated the same way —
    /// see <c>Tenants.IsKnown</c>. A padded claim behaving differently depending on which
    /// identifier it is would be a trap for whoever next touches token issuance.
    /// </remarks>
    private static bool TryRank(string? role, out int rank)
    {
        rank = 0;

        return !string.IsNullOrWhiteSpace(role) && Ranks.TryGetValue(role.Trim(), out rank);
    }
}
