using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.Auth;

/// <inheritdoc cref="ITokenService"/>
public sealed class JwtTokenService : ITokenService
{
    private readonly JwtOptions _options;
    private readonly IClock _clock;

    public JwtTokenService(IOptions<JwtOptions> options, IClock clock)
    {
        _options = options.Value;
        _clock = clock;
    }

    public AccessToken Issue(UserAccount user)
    {
        // Validate on the way *out* as well as on the way in. An unknown tenant or role that gets
        // signed here becomes trusted input everywhere else, so this is the cheapest place to stop
        // it.
        if (!Tenants.IsKnown(user.TenantId))
        {
            throw new InvalidOperationException(
                $"Refusing to issue a token for unknown tenant '{user.TenantId}'.");
        }

        if (!Roles.IsKnown(user.Role))
        {
            throw new InvalidOperationException(
                $"Refusing to issue a token for unknown role '{user.Role}'.");
        }

        var issuedAt = _clock.UtcNow;
        var expiresAt = issuedAt.AddMinutes(_options.AccessTokenLifetimeMinutes);

        var claims = new[]
        {
            new Claim(RegulatedAiClaims.Subject, user.UserId),
            new Claim(RegulatedAiClaims.TenantId, user.TenantId),
            new Claim(RegulatedAiClaims.Role, user.Role),
            new Claim(RegulatedAiClaims.TokenId, Guid.NewGuid().ToString("n")),
        };

        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: issuedAt.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: credentials);

        // The shared handler, so claim names are written exactly as declared rather than being
        // rewritten by the default outbound map.
        var value = JwtBearerConfiguration.CreateTokenHandler().WriteToken(token);

        return new AccessToken(value, expiresAt);
    }
}
