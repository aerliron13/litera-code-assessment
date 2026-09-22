namespace RegulatedAi.Core.Contracts;

/// <summary>
/// A stored evidence document. <see cref="TenantId"/> is part of the record, not an ambient
/// concern: there is no way to hold a document without also holding the tenant it belongs to.
/// </summary>
/// <param name="SubjectId">
/// The vendor (or other subject) this document concerns, or <see cref="AllSubjects"/> for
/// tenant-wide documents such as policies.
/// </param>
/// <param name="ExpiresAtUtc">
/// Null means "does not expire". An expired document still exists and is still retrieved — it
/// simply stops satisfying a requirement, which is what produces a medium-risk band.
/// </param>
public sealed record EvidenceDocument(
    string DocumentId,
    string TenantId,
    string SubjectId,
    string Title,
    string DocumentType,
    string Text,
    IReadOnlyList<string> EvidenceTags,
    DateTimeOffset? ExpiresAtUtc)
{
    /// <summary>Sentinel <see cref="SubjectId"/> for documents that apply across the whole tenant.</summary>
    public const string AllSubjects = "*";

    public bool AppliesToSubject(string subjectId) =>
        SubjectId == AllSubjects || string.Equals(SubjectId, subjectId, StringComparison.OrdinalIgnoreCase);

    public bool IsExpiredAt(DateTimeOffset asOf) => ExpiresAtUtc is not null && ExpiresAtUtc <= asOf;
}
