using RegulatedAi.Core.Actions;
using RegulatedAi.Core.Approvals;
using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Evidence;
using RegulatedAi.Core.Risk;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Core.Workflow;

/// <inheritdoc cref="IWorkflowService"/>
public sealed class WorkflowService : IWorkflowService
{
    private readonly IEvidenceService _evidence;
    private readonly IRiskService _risk;
    private readonly IApprovalService _approvals;
    private readonly IActionService _actions;
    private readonly IAuditService _audit;
    private readonly IPromptInjectionScanner _scanner;

    public WorkflowService(
        IEvidenceService evidence,
        IRiskService risk,
        IApprovalService approvals,
        IActionService actions,
        IAuditService audit,
        IPromptInjectionScanner scanner)
    {
        _evidence = evidence;
        _risk = risk;
        _approvals = approvals;
        _actions = actions;
        _audit = audit;
        _scanner = scanner;
    }

    public async Task<WorkflowResult> RunWorkflowAsync(
        WorkflowRequest request,
        CancellationToken cancellationToken = default)
    {
        await ValidateRequestAsync(request, cancellationToken).ConfigureAwait(false);

        // --- 0. Screen the caller's own input, before anything is retrieved -------------------
        await RejectInjectedQuestionAsync(request, cancellationToken).ConfigureAwait(false);

        // --- 1. Retrieve, tenant-scoped -------------------------------------------------------
        var snippets = await _evidence
            .SearchEvidenceAsync(request.TenantId, request.SubjectId, request.Question, cancellationToken)
            .ConfigureAwait(false);

        // --- 2. Quarantine untrusted content, and record the attempt --------------------------
        var quarantined = snippets
            .Where(snippet => !snippet.IsTrusted)
            .Select(snippet => new QuarantinedEvidence(snippet.DocumentId, snippet.InjectionPatterns))
            .ToArray();

        foreach (var item in quarantined)
        {
            // An injection attempt is a security event in its own right. Pattern names only —
            // never the offending text.
            await _audit.WriteAsync(
                new AuditEvent
                {
                    TenantId = request.TenantId,
                    UserId = request.UserId,
                    Role = request.Role,
                    EventType = AuditEventTypes.EvidenceQuarantined,
                    Action = request.RequestedAction,
                    SubjectId = request.SubjectId,
                    Detail = $"Document '{item.DocumentId}' quarantined as untrusted content.",
                    Reasons = item.MatchedPatterns,
                    CorrelationId = request.CorrelationId,
                },
                cancellationToken)
                .ConfigureAwait(false);
        }

        // --- 3. Evaluate risk over the retrieved set -----------------------------------------
        var assessment = _risk.EvaluateRisk(request.RequestedAction, request.SubjectId, snippets);

        // --- 4. Decide whether this needs a human --------------------------------------------
        var handler = _actions.FindHandler(request.RequestedAction);
        var actionRequested = !string.IsNullOrWhiteSpace(request.RequestedAction);

        var requiresApproval = assessment.RiskLevel == RiskLevel.High
                               || (handler?.AlwaysRequiresApproval ?? false);

        var status = ActionStatus.NotRequested;
        var actionDetail = "No action was requested; this run is advisory only.";
        ApprovalRecord? verifiedApproval = null;

        if (actionRequested)
        {
            if (handler is null)
            {
                // Fails closed: an unknown action name is refused, not ignored.
                var outcome = ActionOutcome.Unsupported(request.RequestedAction!);
                status = outcome.Status;
                actionDetail = outcome.Detail;
            }
            else
            {
                // --- 5. The approval gate ----------------------------------------------------
                if (requiresApproval)
                {
                    var decision = await _approvals
                        .VerifyApprovalAsync(
                            request.TenantId,
                            request.UserId,
                            handler.ActionName,
                            request.SubjectId,
                            request.ApprovedBy,
                            cancellationToken)
                        .ConfigureAwait(false);

                    if (decision.IsApproved)
                    {
                        verifiedApproval = decision.Record;
                    }
                    else
                    {
                        status = ActionStatus.BlockedPendingApproval;
                        actionDetail = decision.Reason;
                    }
                }

                // --- 6. Role gate, then execute ----------------------------------------------
                if (status != ActionStatus.BlockedPendingApproval)
                {
                    if (!Roles.Satisfies(request.Role, handler.MinimumRole))
                    {
                        var outcome = ActionOutcome.DeniedInsufficientRole(request.Role, handler.MinimumRole);
                        status = outcome.Status;
                        actionDetail = outcome.Detail;
                    }
                    else
                    {
                        var outcome = await _actions
                            .ExecuteAsync(
                                new ActionExecutionContext(
                                    request.TenantId,
                                    request.UserId,
                                    request.Role,
                                    handler.ActionName,
                                    request.SubjectId,
                                    assessment.RiskLevel,
                                    verifiedApproval,
                                    request.CorrelationId),
                                cancellationToken)
                            .ConfigureAwait(false);

                        status = outcome.Status;
                        actionDetail = outcome.Detail;
                    }
                }
            }

            // --- 7. Audit the attempt, whatever its outcome ----------------------------------
            await _audit.WriteAsync(
                new AuditEvent
                {
                    TenantId = request.TenantId,
                    UserId = request.UserId,
                    Role = request.Role,
                    EventType = AuditEventTypes.ForActionStatus(status),
                    Action = request.RequestedAction,
                    SubjectId = request.SubjectId,
                    RiskLevel = assessment.RiskLevel,
                    ActionStatus = status,
                    Detail = actionDetail,
                    CorrelationId = request.CorrelationId,
                },
                cancellationToken)
                .ConfigureAwait(false);
        }

        var result = new WorkflowResult
        {
            RiskLevel = assessment.RiskLevel,
            Recommendation = assessment.Recommendation,
            Reasons = assessment.Reasons,
            Citations = assessment.Citations,
            MissingEvidence = assessment.MissingEvidence,
            RequiresApproval = requiresApproval,
            ActionStatus = status,
            ActionDetail = actionDetail,
            QuarantinedEvidence = quarantined,
            CorrelationId = request.CorrelationId,
        };

        // --- 8. Audit the run ------------------------------------------------------------------
        // Written before validation so the decision is on record even if the response is rejected
        // in step 9 — an audit trail with a gap where something went wrong is the worst outcome.
        await _audit.WriteAsync(
            new AuditEvent
            {
                TenantId = request.TenantId,
                UserId = request.UserId,
                Role = request.Role,
                EventType = AuditEventTypes.WorkflowRun,
                Action = request.RequestedAction,
                SubjectId = request.SubjectId,
                RiskLevel = assessment.RiskLevel,
                ActionStatus = status,
                Detail = assessment.Recommendation,
                Reasons = assessment.Reasons,
                CorrelationId = request.CorrelationId,
            },
            cancellationToken)
            .ConfigureAwait(false);

        // --- 9. Constrain the output before it leaves the process -----------------------------
        var validation = new WorkflowValidationContext(
            request.TenantId,
            request.RequestedAction,
            snippets.Select(snippet => snippet.DocumentId).ToHashSet(StringComparer.OrdinalIgnoreCase),
            quarantined.Select(item => item.DocumentId).ToHashSet(StringComparer.OrdinalIgnoreCase),
            verifiedApproval is not null);

        var violations = WorkflowResultValidator.Inspect(result, validation);

        if (violations.Count > 0)
        {
            await _audit.WriteAsync(
                new AuditEvent
                {
                    TenantId = request.TenantId,
                    UserId = request.UserId,
                    Role = request.Role,
                    EventType = AuditEventTypes.OutputValidationFailed,
                    Action = request.RequestedAction,
                    SubjectId = request.SubjectId,
                    RiskLevel = assessment.RiskLevel,
                    ActionStatus = status,
                    Detail = "Response withheld: output contract violated.",
                    Reasons = violations,
                    CorrelationId = request.CorrelationId,
                },
                cancellationToken)
                .ConfigureAwait(false);

            throw new WorkflowContractViolationException(violations);
        }

        return result;
    }

    /// <summary>
    /// Screens the caller's question for instruction-like content and refuses the run if it finds
    /// any.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There are two places untrusted text enters this system, and they need different treatment.
    /// Retrieved documents are screened at the retrieval boundary and <i>quarantined</i>, because
    /// a tenant's own corpus may legitimately contain a poisoned upload and the right answer is to
    /// keep the document, exclude it from scoring and flag it for a human.
    /// </para>
    /// <para>
    /// The question is different: it is the caller's own text, written for this request. There is
    /// no legitimate reason for it to say "ignore previous instructions", so it is refused outright
    /// rather than processed and scored. Refusing early also means a hostile prompt never reaches
    /// retrieval, so it cannot influence which documents come back — the one place free text does
    /// have leverage in this design, since it drives relevance ordering.
    /// </para>
    /// <para>
    /// The trade-off is a false positive on an unusually worded but benign question. That is
    /// acceptable here because the cost is a clear 400 the caller can immediately rephrase, and
    /// the scan runs before any state changes.
    /// </para>
    /// </remarks>
    private async Task RejectInjectedQuestionAsync(
        WorkflowRequest request,
        CancellationToken cancellationToken)
    {
        var scan = _scanner.Scan(request.Question);

        if (!scan.IsSuspicious)
        {
            return;
        }

        await _audit.WriteAsync(
            new AuditEvent
            {
                TenantId = request.TenantId,
                UserId = request.UserId,
                Role = request.Role,
                EventType = AuditEventTypes.RequestInjectionRejected,
                Action = request.RequestedAction,
                SubjectId = request.SubjectId,
                Detail = "The submitted question contained instruction-like content and was refused.",

                // Pattern names, never the submitted text.
                Reasons = scan.MatchedPatterns,
                CorrelationId = request.CorrelationId,
            },
            cancellationToken)
            .ConfigureAwait(false);

        throw new InvalidWorkflowRequestException(
            "The submitted question contained instruction-like content and was refused. Ask the "
            + "question plainly; the engine does not take instructions from request text.");
    }

    /// <summary>
    /// Rejects requests the engine will not act on, and records the rejection.
    /// </summary>
    /// <remarks>
    /// Tenant, user and role are asserted here as invariants rather than validated as input: by
    /// the time a request reaches this method they came from verified token claims, so a blank one
    /// means a programming error upstream, not a bad caller.
    /// </remarks>
    private async Task ValidateRequestAsync(WorkflowRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.TenantId)
            || string.IsNullOrWhiteSpace(request.UserId)
            || string.IsNullOrWhiteSpace(request.Role))
        {
            throw new InvalidOperationException(
                "Tenant, user and role must be populated from verified claims before the workflow runs.");
        }

        if (string.IsNullOrWhiteSpace(request.CorrelationId))
        {
            throw new InvalidOperationException("A correlation id is required so the run can be traced.");
        }

        var failure = string.IsNullOrWhiteSpace(request.SubjectId)
            ? "A subjectId is required: the engine does not infer the action's target from the question."
            : string.IsNullOrWhiteSpace(request.Question)
                ? "A question is required."
                : null;

        if (failure is null)
        {
            return;
        }

        await _audit.WriteAsync(
            new AuditEvent
            {
                TenantId = request.TenantId,
                UserId = request.UserId,
                Role = request.Role,
                EventType = AuditEventTypes.WorkflowRejected,
                Action = request.RequestedAction,
                SubjectId = request.SubjectId,
                Detail = failure,
                CorrelationId = request.CorrelationId,
            },
            cancellationToken)
            .ConfigureAwait(false);

        throw new InvalidWorkflowRequestException(failure);
    }
}
