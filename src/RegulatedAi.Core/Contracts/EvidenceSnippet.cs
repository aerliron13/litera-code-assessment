namespace RegulatedAi.Core.Contracts;

/// <summary>
/// A retrieved snippet. This is the only shape in which retrieved content crosses into the risk
/// layer, and it carries its own trust verdict so that no downstream consumer can forget to ask.
/// </summary>
/// <param name="IsTrusted">
/// False when the injection scanner matched instruction-like content. Untrusted snippets are
/// retrieved and reported, but never satisfy a requirement and never become a citation.
/// </param>
/// <param name="InjectionPatterns">Names of the matched patterns. Never the offending text.</param>
public sealed record EvidenceSnippet(
    string DocumentId,
    string SubjectId,
    string Title,
    string DocumentType,
    string Snippet,
    IReadOnlyList<string> EvidenceTags,
    DateTimeOffset? ExpiresAtUtc,
    bool IsTrusted,
    IReadOnlyList<string> InjectionPatterns)
{
    public bool IsExpiredAt(DateTimeOffset asOf) => ExpiresAtUtc is not null && ExpiresAtUtc <= asOf;

    public bool HasTag(string tag) => EvidenceTags.Contains(tag, StringComparer.OrdinalIgnoreCase);
}
