using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Core.Approvals;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.Controllers;

/// <summary>
/// Where approvals actually come from.
/// </summary>
/// <remarks>
/// Recording an approval is a separate, role-restricted operation rather than a field on the
/// workflow request. That separation is what makes the approval gate meaningful: the user who
/// wants the risky action taken is not the user who can authorise it.
/// </remarks>
[Route("api/approvals")]
[Authorize]
public sealed class ApprovalsController : BaseRegulatedAiTenantController
{
    private readonly IApprovalService _approvals;

    public ApprovalsController(IApprovalService approvals) => _approvals = approvals;

    /// <summary>Records an approval for one action on one subject, within the caller's tenant.</summary>
    [HttpPost]
    [Authorize(Roles = Roles.Approver)]
    [ProducesResponseType(typeof(ApprovalRecord), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<ApprovalRecord>> Record(
        [FromBody] RecordApprovalRequest request,
        CancellationToken cancellationToken)
    {
        var record = await _approvals
            .RecordApprovalAsync(
                TenantId,
                UserId,
                CallerRole,
                request.Action,
                request.SubjectId,
                request.Justification,
                cancellationToken)
            .ConfigureAwait(false);

        return CreatedAtAction(nameof(List), new { }, record);
    }

    /// <summary>Approvals recorded in the caller's tenant. Readable by any authenticated role.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<ApprovalRecord>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<ApprovalRecord>>> List(CancellationToken cancellationToken)
    {
        var records = await _approvals
            .GetForTenantAsync(TenantId, cancellationToken)
            .ConfigureAwait(false);

        return Ok(records);
    }
}
