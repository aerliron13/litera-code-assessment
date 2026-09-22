namespace RegulatedAi.Core.Contracts;

/// <summary>A pointer back to the tenant document that justifies a stated reason.</summary>
public sealed record Citation(string DocumentId, string Snippet);

/// <summary>
/// Reported instead of a citation when a retrieved document was rejected as untrusted.
/// Deliberately carries no snippet text: the point of quarantining content is not to
/// propagate it, and audit records and logs must stay safe to read.
/// </summary>
public sealed record QuarantinedEvidence(string DocumentId, IReadOnlyList<string> MatchedPatterns);
