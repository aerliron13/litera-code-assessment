using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.Auth;

/// <summary>
/// How a bearer token is validated.
/// </summary>
/// <remarks>
/// Extracted from <c>Program.cs</c> so it can be exercised directly. Token validation is the
/// hinge the entire tenant-isolation story hangs from — if a tampered token is accepted, every
/// downstream control is reading attacker-supplied claims — and a security property that important
/// should be asserted by a test rather than assumed from a call to <c>AddJwtBearer</c>.
/// </remarks>
public static class JwtBearerConfiguration
{
    /// <summary>
    /// The token handler used to both write and read tokens.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The claim-name mapping is configured <b>on the instance</b>, deliberately. Left to its
    /// defaults, <see cref="JwtSecurityTokenHandler"/> rewrites <c>sub</c> into
    /// <c>…/nameidentifier</c> and <c>role</c> into <c>…/claims/role</c> on the way in — so the
    /// claim names the token carries are not the claim names application code sees.
    /// </para>
    /// <para>
    /// The usual fix is to clear the static <c>DefaultInboundClaimTypeMap</c> at startup, and that
    /// is what this service used to do. It works, but it makes correct claim names depend on
    /// process-global state that one composition root happens to have mutated: any other code path
    /// that builds a handler — a test, a background worker, a second host — silently gets
    /// different claim names. Configuring the instance keeps the behaviour with the thing that
    /// depends on it.
    /// </para>
    /// </remarks>
    public static JwtSecurityTokenHandler CreateTokenHandler()
    {
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };

        // Likewise on the way out: claim names go on the wire exactly as written.
        handler.OutboundClaimTypeMap.Clear();

        return handler;
    }

    /// <summary>
    /// The validation rules. Every check is switched on explicitly rather than left to defaults,
    /// because the defaults are permissive in exactly the places that matter.
    /// </summary>
    public static TokenValidationParameters CreateTokenValidationParameters(JwtOptions options) => new()
    {
        ValidateIssuer = true,
        ValidIssuer = options.Issuer,

        ValidateAudience = true,
        ValidAudience = options.Audience,

        // The signature check. This is what makes a claim trustworthy: a caller can read and
        // rewrite the payload freely, but cannot produce a matching signature without the key.
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.SigningKey)),

        ValidateLifetime = true,

        // Zero by default. The framework's five-minute grace means an expired token keeps working
        // for five more minutes, which is not a trade this service needs to make.
        ClockSkew = TimeSpan.FromSeconds(options.ClockSkewSeconds),

        // Pin the algorithm. Without this, a token that nominates a different algorithm — "none"
        // included — is worth attempting.
        ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },

        NameClaimType = RegulatedAiClaims.Subject,
        RoleClaimType = RegulatedAiClaims.Role,
    };

    /// <summary>
    /// The check applied after the signature verifies: a correctly signed token is still unusable
    /// unless it names a tenant and a role this service recognises.
    /// </summary>
    /// <returns>
    /// Null when the principal is usable, otherwise the reason to fail authentication with.
    /// </returns>
    /// <remarks>
    /// Returning a reason rather than throwing keeps this a pure function of the principal, which
    /// is what makes it testable without a request pipeline.
    /// </remarks>
    public static string? DescribeClaimFailure(ClaimsPrincipal? principal)
    {
        var tenantId = principal?.FindFirst(RegulatedAiClaims.TenantId)?.Value;
        var role = principal?.FindFirst(RegulatedAiClaims.Role)?.Value;
        var subject = principal?.FindFirst(RegulatedAiClaims.Subject)?.Value;

        if (string.IsNullOrWhiteSpace(subject))
        {
            return "The token does not carry a sub claim.";
        }

        if (!Tenants.IsKnown(tenantId))
        {
            return "The token does not carry a recognised tenant_id claim.";
        }

        return Roles.IsKnown(role) ? null : "The token does not carry a recognised role claim.";
    }
}
