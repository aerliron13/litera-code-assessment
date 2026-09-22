using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Api.Auth;

namespace RegulatedAi.Api.Controllers;

/// <summary>
/// Base class for every endpoint that operates inside a tenant.
/// </summary>
/// <remarks>
/// <para>
/// Carries the two things every tenant-scoped endpoint needs and must not get wrong:
/// <see cref="Authorize"/> is applied here rather than per controller, so a new endpoint is
/// authenticated by default and opting out has to be deliberate and visible; and
/// <see cref="Caller"/> is the single accessor for tenant, user and role, so no controller is
/// tempted to read a claim — or worse, a request field — for itself.
/// </para>
/// <para>
/// <c>AuthController</c> deliberately does <i>not</i> derive from this class: it is the endpoint
/// that exists to establish identity, so it has no caller to scope to.
/// </para>
/// </remarks>
[ApiController]
[Authorize]
[Produces("application/json")]
public abstract class BaseRegulatedAiTenantController : ControllerBase
{
    private CallerContext? _caller;

    /// <summary>
    /// The verified caller. Resolved once per request from token claims, and throws
    /// <see cref="UnauthorizedAccessException"/> — mapped to 401 — if the claims are unusable.
    /// </summary>
    protected CallerContext Caller => _caller ??= User.ToCaller();

    /// <summary>The caller's tenant. Every store and service call in a derived controller uses this.</summary>
    protected string TenantId => Caller.TenantId;

    protected string UserId => Caller.UserId;

    protected string CallerRole => Caller.Role;

    /// <summary>Ties a response, its audit events and its log lines together.</summary>
    protected string CorrelationId => HttpContext.TraceIdentifier;
}
