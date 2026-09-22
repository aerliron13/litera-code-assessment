using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Core.Evidence;

/// <summary>
/// Tenant-scoped retrieval. The exercise's <c>searchEvidence</c>.
/// </summary>
public interface IEvidenceService
{
    /// <summary>
    /// Returns every document in <paramref name="tenantId"/> that applies to
    /// <paramref name="subjectId"/>, ordered by relevance to <paramref name="query"/> and screened
    /// for injected instructions.
    /// </summary>
    /// <remarks>
    /// <b>Recall is a security property here.</b> <paramref name="query"/> affects *ordering* and
    /// snippet selection, never inclusion. A relevance cut-off would mean a badly worded question
    /// could drop the SOC 2 report from the result set, and a missing document reads downstream as
    /// a satisfied requirement — silently lowering risk. Filtering by subject and tenant is the
    /// only filtering allowed to remove a document.
    /// </remarks>
    Task<IReadOnlyList<EvidenceSnippet>> SearchEvidenceAsync(
        string tenantId,
        string subjectId,
        string query,
        CancellationToken cancellationToken = default);
}
