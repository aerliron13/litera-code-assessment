using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Workflow;

namespace RegulatedAi.Api.Controllers;

/// <summary>The orchestrator's HTTP surface.</summary>
/// <remarks>
/// <see cref="AuthorizeAttribute"/> is stated here as well as on the base class. It is redundant
/// by design: the base guarantees a new controller is authenticated even if someone forgets, and
/// the local attribute means a reader of this file does not have to go and check.
/// </remarks>
[Route("api/workflow")]
[Authorize]
public sealed class WorkflowController : BaseRegulatedAiTenantController
{
    private readonly IWorkflowService _workflow;

    public WorkflowController(IWorkflowService workflow) => _workflow = workflow;

    /// <summary>
    /// Retrieves tenant-scoped evidence, evaluates risk, gates the requested action behind a
    /// recorded approval, audits the run and the attempt, and returns a validated recommendation.
    /// </summary>
    [HttpPost("run")]
    [ProducesResponseType(typeof(WorkflowResult), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<WorkflowResult>> Run(
        [FromBody] RunWorkflowRequest request,
        CancellationToken cancellationToken)
    {
        // The one place claims become a workflow request. Identity comes from the token via the
        // base controller; only the question, the subject and the approval reference come from the
        // body.
        var workflowRequest = new WorkflowRequest(
            TenantId,
            UserId,
            CallerRole,
            request.Question,
            request.RequestedAction,
            request.SubjectId,
            request.ApprovedBy,
            CorrelationId);

        var result = await _workflow
            .RunWorkflowAsync(workflowRequest, cancellationToken)
            .ConfigureAwait(false);

        return Ok(result);
    }
}
