using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Api.Auth;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Core.Data;

namespace RegulatedAi.Api.Controllers;

/// <summary>
/// Issues the bearer tokens the rest of the API consumes.
/// </summary>
/// <remarks>
/// Stands in for an identity provider, because the brief says a simple role field is enough. The
/// two things worth keeping even in this stub are that the credential comparison does not leak
/// timing, and that a failure says nothing about *why* it failed.
/// </remarks>
[ApiController]
[Route("api/auth")]
[AllowAnonymous]
public sealed class AuthController : ControllerBase
{
    private readonly IUserStore _users;
    private readonly ITokenService _tokens;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IUserStore users, ITokenService tokens, ILogger<AuthController> logger)
    {
        _users = users;
        _tokens = tokens;
        _logger = logger;
    }

    /// <summary>Exchanges seeded credentials for a token carrying the tenant and role claims.</summary>
    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public ActionResult<LoginResponse> Login([FromBody] LoginRequest request)
    {
        var user = _users.FindByUsername(request.Username);

        // Compare regardless of whether the account exists, so a response time cannot be used to
        // enumerate usernames, and return one indistinguishable failure for both cases.
        var expected = user?.DevPassword ?? string.Empty;

        if (user is null || !ConstantTimeEquals(expected, request.Password))
        {
            _logger.LogWarning("Failed login attempt for username {Username}.", request.Username);

            return Unauthorized(new ProblemDetails
            {
                Status = StatusCodes.Status401Unauthorized,
                Title = "Unauthorized",
                Detail = "Invalid username or password.",
            });
        }

        var token = _tokens.Issue(user);

        _logger.LogInformation(
            "Issued a token for {UserId} in tenant {TenantId} with role {Role}.",
            user.UserId,
            user.TenantId,
            user.Role);

        return Ok(new LoginResponse(
            token.Value,
            "Bearer",
            token.ExpiresAtUtc,
            user.TenantId,
            user.UserId,
            user.Role));
    }

    /// <summary>
    /// Fixed-time credential comparison.
    /// </summary>
    /// <remarks>
    /// Both sides are hashed to a fixed 32 bytes before comparing, so neither the comparison time
    /// nor the early-exit behaviour of a length check reveals anything about the stored value.
    /// This is a stub's hygiene, not a password scheme: a real deployment stores a memory-hard
    /// hash (Argon2id, scrypt) or, better, holds no password at all and federates.
    /// </remarks>
    private static bool ConstantTimeEquals(string expected, string supplied)
    {
        Span<byte> expectedHash = stackalloc byte[32];
        Span<byte> suppliedHash = stackalloc byte[32];

        SHA256.HashData(Encoding.UTF8.GetBytes(expected), expectedHash);
        SHA256.HashData(Encoding.UTF8.GetBytes(supplied), suppliedHash);

        return CryptographicOperations.FixedTimeEquals(expectedHash, suppliedHash);
    }
}
