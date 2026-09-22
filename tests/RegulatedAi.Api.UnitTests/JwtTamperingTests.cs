using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using Moq;
using RegulatedAi.Api.Auth;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.UnitTests;

/// <summary>
/// What happens when a caller edits a token after login.
/// </summary>
/// <remarks>
/// <para>
/// A JWT is not secret and not tamper-proof: anyone holding one can base64url-decode the payload,
/// read every claim, change any of them, and re-encode. Nothing prevents that. What prevents it
/// from <i>mattering</i> is the signature — the edited payload no longer matches, and validation
/// fails before a single claim is read by application code.
/// </para>
/// <para>
/// That is the load-bearing assumption under this entire design. Tenant isolation, the role gate
/// and the approval gate all read claims and trust them; if a self-promoted <c>tenant_id</c> or
/// <c>role</c> survived validation, every one of those controls would be reading attacker input.
/// So these tests tamper with real tokens the way an attacker would and assert the rejection,
/// rather than assuming <c>AddJwtBearer</c> was configured correctly.
/// </para>
/// </remarks>
public sealed class JwtTamperingTests
{
    private const string SigningKey = "TEST-ONLY-SIGNING-KEY-NOT-A-SECRET-0123456789abcdef";
    private const string AttackerKey = "ATTACKER-CONTROLLED-KEY-ALSO-LONG-ENOUGH-0123456789";

    private static readonly DateTimeOffset Now = new(2026, 1, 15, 9, 0, 0, TimeSpan.Zero);

    private static JwtOptions Options() => new()
    {
        Issuer = "test-issuer",
        Audience = "test-audience",
        SigningKey = SigningKey,
        SeedUserPassword = "Passw0rd!",
        AccessTokenLifetimeMinutes = 30,
    };

    /// <summary>A genuine token, issued exactly as the login endpoint issues one.</summary>
    private static string IssueGenuineToken(
        string tenantId = Tenants.A,
        string role = Roles.Analyst,
        string userId = "alice")
    {
        var clock = new Mock<IClock>();
        clock.SetupGet(instance => instance.UtcNow).Returns(Now);

        var service = new JwtTokenService(
            Microsoft.Extensions.Options.Options.Create(Options()), clock.Object);

        return service.Issue(new UserAccount(userId, userId, "Passw0rd!", tenantId, role)).Value;
    }

    /// <summary>
    /// Validates a token the way the API does, with the clock pinned so lifetime checks are
    /// deterministic.
    /// </summary>
    private static ClaimsPrincipal Validate(string token, DateTime? asOf = null)
    {
        var parameters = JwtBearerConfiguration.CreateTokenValidationParameters(Options());

        // LifetimeValidator lets the test choose "now" without waiting for real time to pass.
        var at = asOf ?? Now.UtcDateTime.AddMinutes(1);
        parameters.LifetimeValidator = (notBefore, expires, _, _) =>
            (notBefore is null || notBefore <= at) && (expires is null || expires > at);

        return JwtBearerConfiguration.CreateTokenHandler().ValidateToken(token, parameters, out _);
    }

    // -------------------------------------------------------------------------------------------
    // Tampering helpers — exactly what a caller with a token and five minutes can do
    // -------------------------------------------------------------------------------------------

    private static string Base64UrlDecodeToJson(string segment) =>
        Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(segment));

    private static string Base64UrlEncodeJson(string json) =>
        Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));

    /// <summary>Rewrites a payload claim and reattaches the ORIGINAL signature.</summary>
    private static string TamperPayload(string token, string claim, string newValue)
    {
        var parts = token.Split('.');
        var payload = JsonNode.Parse(Base64UrlDecodeToJson(parts[1]))!.AsObject();

        payload[claim] = newValue;

        return string.Join('.', parts[0], Base64UrlEncodeJson(payload.ToJsonString()), parts[2]);
    }

    /// <summary>Rewrites a claim and re-signs with a key the attacker controls.</summary>
    private static string TamperAndResign(string token, string claim, string newValue)
    {
        var parts = token.Split('.');
        var payload = JsonNode.Parse(Base64UrlDecodeToJson(parts[1]))!.AsObject();

        payload[claim] = newValue;

        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AttackerKey)),
            SecurityAlgorithms.HmacSha256);

        var claims = payload
            .Where(pair => pair.Key is not ("exp" or "nbf" or "iss" or "aud"))
            .Select(pair => new Claim(pair.Key, pair.Value!.ToString()))
            .ToArray();

        var forged = new JwtSecurityToken(
            issuer: "test-issuer",
            audience: "test-audience",
            claims: claims,
            notBefore: Now.UtcDateTime,
            expires: Now.UtcDateTime.AddMinutes(30),
            signingCredentials: credentials);

        return JwtBearerConfiguration.CreateTokenHandler().WriteToken(forged);
    }

    // -------------------------------------------------------------------------------------------
    // The baseline: an untouched token works and its claims survive intact
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void An_untouched_token_validates_and_keeps_its_claims()
    {
        var principal = Validate(IssueGenuineToken(Tenants.A, Roles.Analyst));

        Assert.Equal(Tenants.A, principal.FindFirst(RegulatedAiClaims.TenantId)!.Value);
        Assert.Equal(Roles.Analyst, principal.FindFirst(RegulatedAiClaims.Role)!.Value);
        Assert.Equal("alice", principal.FindFirst(RegulatedAiClaims.Subject)!.Value);
    }

    /// <summary>
    /// Worth stating plainly: the claims are readable by anyone holding the token. A JWT is
    /// signed, not encrypted, so nothing secret belongs in one.
    /// </summary>
    [Fact]
    public void The_payload_is_readable_by_anyone_holding_the_token()
    {
        var payload = Base64UrlDecodeToJson(IssueGenuineToken().Split('.')[1]);

        Assert.Contains(Tenants.A, payload);
        Assert.Contains("alice", payload);
    }

    // -------------------------------------------------------------------------------------------
    // Tampering with the payload, keeping the original signature
    //
    // These assert SecurityTokenException rather than a specific subtype. Which subtype surfaces
    // is a detail of the validation library — a tampered HS256 payload with no `kid` reports as
    // SecurityTokenSignatureKeyNotFoundException, not SecurityTokenInvalidSignatureException — and
    // pinning it would make the tests fail on a library upgrade for no security-relevant reason.
    // The property that matters is that no ClaimsPrincipal is produced.
    // -------------------------------------------------------------------------------------------

    /// <summary>Self-promotion to another tenant — the attack tenant isolation depends on failing.</summary>
    [Fact]
    public void Editing_the_tenant_claim_invalidates_the_token()
    {
        var tampered = TamperPayload(IssueGenuineToken(Tenants.A), RegulatedAiClaims.TenantId, Tenants.B);

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(tampered));
    }

    /// <summary>Self-promotion from analyst to approver — the attack the role gate depends on failing.</summary>
    [Fact]
    public void Editing_the_role_claim_invalidates_the_token()
    {
        var tampered = TamperPayload(
            IssueGenuineToken(role: Roles.Analyst), RegulatedAiClaims.Role, Roles.Approver);

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(tampered));
    }

    /// <summary>
    /// Impersonating another user would also defeat separation of duties: the approval gate
    /// refuses self-approval by comparing the requester's <c>sub</c> to the recorded approver.
    /// </summary>
    [Fact]
    public void Editing_the_subject_claim_invalidates_the_token()
    {
        var tampered = TamperPayload(IssueGenuineToken(), RegulatedAiClaims.Subject, "dave");

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(tampered));
    }

    [Fact]
    public void Extending_the_expiry_claim_invalidates_the_token()
    {
        var token = IssueGenuineToken();
        var parts = token.Split('.');
        var payload = JsonNode.Parse(Base64UrlDecodeToJson(parts[1]))!.AsObject();

        payload["exp"] = DateTimeOffset.UtcNow.AddYears(10).ToUnixTimeSeconds();

        var tampered = string.Join(
            '.', parts[0], Base64UrlEncodeJson(payload.ToJsonString()), parts[2]);

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(tampered));
    }

    [Fact]
    public void Editing_the_issuer_claim_invalidates_the_token()
    {
        var tampered = TamperPayload(IssueGenuineToken(), "iss", "attacker-issuer");

        // Issuer is checked before the signature, so this surfaces as an issuer failure — either
        // way the token does not authenticate.
        Assert.ThrowsAny<SecurityTokenException>(() => Validate(tampered));
    }

    [Fact]
    public void A_truncated_signature_invalidates_the_token()
    {
        var parts = IssueGenuineToken().Split('.');
        var tampered = string.Join('.', parts[0], parts[1], parts[2][..^4]);

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(tampered));
    }

    [Fact]
    public void Dropping_the_signature_entirely_invalidates_the_token()
    {
        var parts = IssueGenuineToken().Split('.');
        var tampered = string.Join('.', parts[0], parts[1], string.Empty);

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(tampered));
    }

    // -------------------------------------------------------------------------------------------
    // Tampering and re-signing with a key the attacker controls
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The more serious attempt: produce a *structurally valid* token with a real signature, just
    /// not one made with our key. Rejected because the key is what is validated, not the presence
    /// of a signature.
    /// </summary>
    [Fact]
    public void A_token_re_signed_with_an_attacker_key_is_rejected()
    {
        var forged = TamperAndResign(
            IssueGenuineToken(Tenants.A), RegulatedAiClaims.TenantId, Tenants.B);

        Assert.Throws<SecurityTokenSignatureKeyNotFoundException>(() => Validate(forged));
    }

    /// <summary>
    /// The classic algorithm-confusion attempt. <c>ValidAlgorithms</c> pins HS256, so a token
    /// nominating anything else is refused before the signature is even considered.
    /// </summary>
    [Fact]
    public void A_token_nominating_the_none_algorithm_is_rejected()
    {
        var parts = IssueGenuineToken().Split('.');
        var header = JsonNode.Parse(Base64UrlDecodeToJson(parts[0]))!.AsObject();

        header["alg"] = "none";

        var forged = string.Join(
            '.', Base64UrlEncodeJson(header.ToJsonString()), parts[1], string.Empty);

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(forged));
    }

    [Fact]
    public void Garbage_in_place_of_a_token_is_rejected() =>
        Assert.ThrowsAny<Exception>(() => Validate("not-a-token-at-all"));

    // -------------------------------------------------------------------------------------------
    // Expiry and the post-signature claim check
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void An_expired_token_is_rejected() =>
        Assert.Throws<SecurityTokenInvalidLifetimeException>(
            () => Validate(IssueGenuineToken(), asOf: Now.UtcDateTime.AddHours(2)));

    /// <summary>
    /// Even a perfectly valid signature is not sufficient. A token we ourselves signed but whose
    /// tenant we no longer recognise — a deprovisioned tenant, say — is refused after validation.
    /// </summary>
    [Fact]
    public void A_correctly_signed_token_naming_an_unknown_tenant_is_refused_after_validation()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(RegulatedAiClaims.Subject, "alice"),
            new Claim(RegulatedAiClaims.TenantId, "tenant-deprovisioned"),
            new Claim(RegulatedAiClaims.Role, Roles.Analyst),
        }));

        var failure = JwtBearerConfiguration.DescribeClaimFailure(principal);

        Assert.NotNull(failure);
        Assert.Contains("tenant_id", failure);
    }

    [Fact]
    public void A_correctly_signed_token_naming_an_unknown_role_is_refused_after_validation()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(RegulatedAiClaims.Subject, "alice"),
            new Claim(RegulatedAiClaims.TenantId, Tenants.A),
            new Claim(RegulatedAiClaims.Role, "superuser"),
        }));

        Assert.Contains("role", JwtBearerConfiguration.DescribeClaimFailure(principal)!);
    }

    [Fact]
    public void A_token_with_no_subject_is_refused_after_validation()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(RegulatedAiClaims.TenantId, Tenants.A),
            new Claim(RegulatedAiClaims.Role, Roles.Analyst),
        }));

        Assert.Contains("sub", JwtBearerConfiguration.DescribeClaimFailure(principal)!);
    }

    [Fact]
    public void A_usable_principal_produces_no_failure_reason()
    {
        var principal = Validate(IssueGenuineToken());

        Assert.Null(JwtBearerConfiguration.DescribeClaimFailure(principal));
    }

    [Fact]
    public void A_null_principal_is_refused() =>
        Assert.NotNull(JwtBearerConfiguration.DescribeClaimFailure(null));

    // -------------------------------------------------------------------------------------------
    // Validation configuration
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void Validation_checks_issuer_audience_signature_and_lifetime()
    {
        var parameters = JwtBearerConfiguration.CreateTokenValidationParameters(Options());

        Assert.True(parameters.ValidateIssuer);
        Assert.True(parameters.ValidateAudience);
        Assert.True(parameters.ValidateIssuerSigningKey);
        Assert.True(parameters.ValidateLifetime);
    }

    [Fact]
    public void Validation_pins_the_signing_algorithm()
    {
        var parameters = JwtBearerConfiguration.CreateTokenValidationParameters(Options());

        Assert.Equal(new[] { SecurityAlgorithms.HmacSha256 }, parameters.ValidAlgorithms);
    }

    [Fact]
    public void Validation_allows_no_clock_skew_by_default()
    {
        var parameters = JwtBearerConfiguration.CreateTokenValidationParameters(Options());

        Assert.Equal(TimeSpan.Zero, parameters.ClockSkew);
    }

    [Fact]
    public void Validation_reads_role_and_name_from_the_short_claim_names()
    {
        var parameters = JwtBearerConfiguration.CreateTokenValidationParameters(Options());

        Assert.Equal(RegulatedAiClaims.Role, parameters.RoleClaimType);
        Assert.Equal(RegulatedAiClaims.Subject, parameters.NameClaimType);
    }
}
