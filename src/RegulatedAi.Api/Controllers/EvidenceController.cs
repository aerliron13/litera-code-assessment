using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Core.Evidence;

namespace RegulatedAi.Api.Controllers;

/// <summary>
/// Direct read access to tenant-scoped evidence retrieval.
/// </summary>
/// <remarks>
/// An inspection endpoint. It makes two properties observable from outside the engine that would
/// otherwise only be visible in a unit test: that retrieval returns nothing for another tenant's
/// subject, and that the malicious document is retrieved but flagged untrusted rather than
/// silently dropped.
/// </remarks>
[Route("api/evidence")]
[Authorize]
public sealed class EvidenceController : BaseRegulatedAiTenantController
{
    private readonly IEvidenceService _evidence;

    public EvidenceController(IEvidenceService evidence) => _evidence = evidence;

    /// <summary>Evidence in the caller's tenant for one subject, ordered by relevance.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<EvidenceSnippetResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<IReadOnlyList<EvidenceSnippetResponse>>> Get(
        [FromQuery] string subjectId,
        [FromQuery] string? query,
        CancellationToken cancellationToken)
    {
        var snippets = await _evidence
            .SearchEvidenceAsync(TenantId, subjectId, query ?? string.Empty, cancellationToken)
            .ConfigureAwait(false);

        return Ok(snippets.Select(EvidenceSnippetResponse.From).ToArray());
    }
}
