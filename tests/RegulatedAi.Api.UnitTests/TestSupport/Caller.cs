using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Api.Auth;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.UnitTests.TestSupport;

/// <summary>
/// Builds the claims principals and controller contexts these tests run against.
/// </summary>
/// <remarks>
/// Controllers are exercised directly rather than through a hosted pipeline: there is no external
/// system to integrate with here, so the only thing an in-process host would add is startup time.
/// What matters is that a controller reads identity from claims and from nowhere else, and that is
/// exactly what constructing the principal by hand lets a test pin down.
/// </remarks>
public static class Caller
{
    public const string CorrelationId = "corr-under-test";

    /// <summary>
    /// A principal with the claims this service issues. Pass null for any claim to omit it, which
    /// is how the "unusable token" cases are expressed.
    /// </summary>
    public static ClaimsPrincipal Principal(
        string? tenantId = Tenants.A,
        string? userId = "alice",
        string? role = Roles.Analyst)
    {
        var claims = new List<Claim>();

        if (tenantId is not null)
        {
            claims.Add(new Claim(RegulatedAiClaims.TenantId, tenantId));
        }

        if (userId is not null)
        {
            claims.Add(new Claim(RegulatedAiClaims.Subject, userId));
        }

        if (role is not null)
        {
            claims.Add(new Claim(RegulatedAiClaims.Role, role));
        }

        // Same claim types the JWT bearer handler is configured with, so role checks and
        // ToCaller() behave here exactly as they do at runtime.
        var identity = new ClaimsIdentity(
            claims,
            authenticationType: "Test",
            nameType: RegulatedAiClaims.Subject,
            roleType: RegulatedAiClaims.Role);

        return new ClaimsPrincipal(identity);
    }

    /// <summary>An anonymous principal, for the "no token" cases.</summary>
    public static ClaimsPrincipal Anonymous() => new(new ClaimsIdentity());

    /// <summary>Attaches a principal to a controller and returns the controller.</summary>
    public static TController As<TController>(this TController controller, ClaimsPrincipal principal)
        where TController : ControllerBase
    {
        var httpContext = new DefaultHttpContext
        {
            User = principal,
            TraceIdentifier = CorrelationId,
        };

        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        return controller;
    }

    /// <summary>Shorthand: attach a principal built from the given claim values.</summary>
    public static TController AsUser<TController>(
        this TController controller,
        string? tenantId = Tenants.A,
        string? userId = "alice",
        string? role = Roles.Analyst)
        where TController : ControllerBase =>
        controller.As(Principal(tenantId, userId, role));
}
