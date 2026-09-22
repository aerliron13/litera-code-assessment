using System.ComponentModel.DataAnnotations;
using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Api.Contracts;

public sealed record LoginRequest
{
    [Required]
    [MaxLength(64)]
    public string Username { get; init; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string Password { get; init; } = string.Empty;
}

public sealed record LoginResponse(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAtUtc,
    string TenantId,
    string UserId,
    string Role);

/// <summary>
/// The workflow request body.
/// </summary>
/// <remarks>
/// <b>Note what is absent.</b> There is no <c>tenantId</c>, no <c>userId</c> and no <c>role</c>
/// field. Those three come from the bearer token and nowhere else, which is why cross-tenant
/// access is not something the API has to defend against request-by-request — the request simply
/// cannot express it.
/// </remarks>
public sealed record RunWorkflowRequest
{
    [Required]
    [MaxLength(1000)]
    public string Question { get; init; } = string.Empty;

    /// <summary>
    /// The subject (vendor) to assess and act on. Explicit rather than inferred from
    /// <see cref="Question"/>: letting free text choose the target of a risky action would hand
    /// target selection to attacker-influenced content.
    /// </summary>
    [Required]
    [MaxLength(128)]
    public string SubjectId { get; init; } = string.Empty;

    /// <summary>Omit for an advisory run that assesses risk without attempting anything.</summary>
    [MaxLength(128)]
    public string? RequestedAction { get; init; }

    /// <summary>
    /// The user whose recorded approval should authorise this action. A <i>reference</i> to an
    /// approval, not an approval: supplying a name with no matching record leaves the action
    /// blocked, and naming yourself is refused.
    /// </summary>
    [MaxLength(64)]
    public string? ApprovedBy { get; init; }
}

public sealed record RecordApprovalRequest
{
    [Required]
    [MaxLength(128)]
    public string Action { get; init; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string SubjectId { get; init; } = string.Empty;

    [Required]
    [MaxLength(500)]
    public string Justification { get; init; } = string.Empty;
}

/// <summary>An evidence snippet as returned by the inspection endpoint.</summary>
/// <remarks>
/// Carries <see cref="IsTrusted"/> and <see cref="InjectionPatterns"/> so that quarantining is
/// observable from outside the engine — the integration tests and the README walkthrough both
/// rely on being able to see that a document was retrieved *and* rejected.
/// </remarks>
public sealed record EvidenceSnippetResponse(
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
    public static EvidenceSnippetResponse From(EvidenceSnippet snippet) => new(
        snippet.DocumentId,
        snippet.SubjectId,
        snippet.Title,
        snippet.DocumentType,
        snippet.Snippet,
        snippet.EvidenceTags,
        snippet.ExpiresAtUtc,
        snippet.IsTrusted,
        snippet.InjectionPatterns);
}
