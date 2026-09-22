using System.Security.Claims;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.Auth;

/// <summary>The claim names this service issues and validates.</summary>
public static class RegulatedAiClaims
{
    public const string Subject = "sub";
    public const string TenantId = "tenant_id";
    public const string Role = "role";
    public const string TokenId = "jti";
}

/// <summary>
/// The caller, as established from verified token claims. This is the only shape in which
/// identity enters the engine.
/// </summary>
public sealed record CallerContext(string TenantId, string UserId, string Role);

/// <summary>
/// Maps a validated <see cref="ClaimsPrincipal"/> to a <see cref="CallerContext"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the whole trust boundary for identity.</b> It is the single place in the solution
/// where tenant, user and role are read, and every one of them comes from a signature-verified
/// claim. No request DTO has fields for them, so there is no path by which a caller can assert
/// its own tenant or promote its own role.
/// </para>
/// <para>
/// The tenant claim is re-checked against the known-tenant registry here even though
/// <c>OnTokenValidated</c> already rejected unknown tenants at authentication. The duplication is
/// deliberate: this method is what the controllers call, so the guarantee should hold for anything
/// that reaches it, including a future endpoint wired up with a different authentication scheme.
/// </para>
/// </remarks>
public static class ClaimsPrincipalExtensions
{
    public static CallerContext ToCaller(this ClaimsPrincipal principal)
    {
        var tenantId = principal.FindFirstValue(RegulatedAiClaims.TenantId);
        var userId = principal.FindFirstValue(RegulatedAiClaims.Subject);
        var role = principal.FindFirstValue(RegulatedAiClaims.Role);

        if (string.IsNullOrWhiteSpace(userId))
        {
            throw new UnauthorizedAccessException("The token carries no subject claim.");
        }

        if (!Tenants.IsKnown(tenantId))
        {
            throw new UnauthorizedAccessException(
                "The token carries no recognised tenant claim; the request cannot be scoped.");
        }

        if (!Roles.IsKnown(role))
        {
            throw new UnauthorizedAccessException("The token carries no recognised role claim.");
        }

        return new CallerContext(tenantId!.Trim(), userId.Trim(), role!.Trim());
    }
}
