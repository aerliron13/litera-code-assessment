using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Api.Controllers;

/// <summary>
/// Read access to the caller's own audit trail.
/// </summary>
/// <remarks>
/// Exists so that the audit trail is demonstrable rather than merely asserted — the integration
/// tests and the README walkthrough both read it back. In production this would not be an
/// application endpoint at all: the trail would live in append-only storage that the application
/// can write to but not read or amend, queried through a separate compliance tool with its own
/// access control.
/// </remarks>
[Route("api/audit")]
[Authorize]
public sealed class AuditController : BaseRegulatedAiTenantController
{
    private readonly IAuditService _audit;

    public AuditController(IAuditService audit) => _audit = audit;

    /// <summary>Audit events for the caller's tenant, oldest first.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<AuditEvent>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<IReadOnlyList<AuditEvent>>> Get(CancellationToken cancellationToken)
    {
        var events = await _audit
            .GetForTenantAsync(TenantId, cancellationToken)
            .ConfigureAwait(false);

        return Ok(events);
    }
}
