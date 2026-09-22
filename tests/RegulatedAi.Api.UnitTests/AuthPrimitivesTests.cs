using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Moq;
using RegulatedAi.Api.Auth;
using RegulatedAi.Api.UnitTests.TestSupport;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.UnitTests;

/// <summary>
/// Claims-to-caller mapping: the single place in the solution where identity enters the engine.
/// </summary>
public sealed class ClaimsPrincipalExtensionsTests
{
    [Fact]
    public void Maps_a_complete_principal_to_a_caller()
    {
        var caller = Caller.Principal(Tenants.B, "erin", Roles.Approver).ToCaller();

        Assert.Equal(Tenants.B, caller.TenantId);
        Assert.Equal("erin", caller.UserId);
        Assert.Equal(Roles.Approver, caller.Role);
    }

    [Fact]
    public void Trims_whitespace_from_claim_values()
    {
        var caller = Caller.Principal(" tenant-a ", " alice ", " analyst ").ToCaller();

        Assert.Equal(Tenants.A, caller.TenantId);
        Assert.Equal("alice", caller.UserId);
        Assert.Equal(Roles.Analyst, caller.Role);
    }

    [Fact]
    public void Rejects_a_principal_with_no_subject() =>
        Assert.Throws<UnauthorizedAccessException>(
            () => Caller.Principal(userId: null).ToCaller());

    [Fact]
    public void Rejects_a_principal_with_no_tenant() =>
        Assert.Throws<UnauthorizedAccessException>(
            () => Caller.Principal(tenantId: null).ToCaller());

    /// <summary>
    /// An unknown tenant is refused rather than used. A tenant id is a storage key: an
    /// unrecognised value does not throw, it addresses an empty partition — which reads as "no
    /// evidence found", which is a plausible-looking high-risk answer about a tenant that does not
    /// exist.
    /// </summary>
    [Theory]
    [InlineData("tenant-does-not-exist")]
    [InlineData("")]
    [InlineData("   ")]
    public void Rejects_a_principal_naming_an_unknown_tenant(string tenantId) =>
        Assert.Throws<UnauthorizedAccessException>(
            () => Caller.Principal(tenantId: tenantId).ToCaller());

    [Theory]
    [InlineData("superuser")]
    [InlineData("")]
    public void Rejects_a_principal_naming_an_unknown_role(string role) =>
        Assert.Throws<UnauthorizedAccessException>(
            () => Caller.Principal(role: role).ToCaller());

    [Fact]
    public void Rejects_an_anonymous_principal() =>
        Assert.Throws<UnauthorizedAccessException>(() => Caller.Anonymous().ToCaller());

    [Fact]
    public void Accepts_a_known_tenant_regardless_of_casing() =>
        Assert.Equal("TENANT-A", Caller.Principal(tenantId: "TENANT-A").ToCaller().TenantId);
}

public sealed class JwtTokenServiceTests
{
    private static JwtOptions Options() => new()
    {
        Issuer = "test-issuer",
        Audience = "test-audience",
        SigningKey = "TEST-ONLY-SIGNING-KEY-NOT-A-SECRET-0123456789abcdef",
        SeedUserPassword = "Passw0rd!",
        AccessTokenLifetimeMinutes = 30,
    };

    private static readonly DateTimeOffset Now = new(2026, 1, 15, 9, 0, 0, TimeSpan.Zero);

    private static JwtTokenService Service()
    {
        var clock = new Mock<IClock>();
        clock.SetupGet(instance => instance.UtcNow).Returns(Now);

        return new JwtTokenService(Microsoft.Extensions.Options.Options.Create(Options()), clock.Object);
    }

    private static UserAccount User(string tenantId = Tenants.A, string role = Roles.Analyst) =>
        new("alice", "alice", "Passw0rd!", tenantId, role);

    [Fact]
    public void Issues_a_token_carrying_the_subject_tenant_and_role_claims()
    {
        var token = Service().Issue(User(Tenants.B, Roles.Approver));

        var parsed = JwtBearerConfiguration.CreateTokenHandler().ReadJwtToken(token.Value);

        Assert.Equal("alice", parsed.Claims.Single(c => c.Type == RegulatedAiClaims.Subject).Value);
        Assert.Equal(Tenants.B, parsed.Claims.Single(c => c.Type == RegulatedAiClaims.TenantId).Value);
        Assert.Equal(Roles.Approver, parsed.Claims.Single(c => c.Type == RegulatedAiClaims.Role).Value);
    }

    [Fact]
    public void Uses_the_short_claim_names_rather_than_legacy_uris()
    {
        var parsed = JwtBearerConfiguration.CreateTokenHandler().ReadJwtToken(Service().Issue(User()).Value);

        // Claim names are part of the contract between the token and the authorization checks, so
        // they must not be silently rewritten into SOAP-era URIs.
        Assert.All(parsed.Claims, claim => Assert.DoesNotContain("schemas.xmlsoap.org", claim.Type));
        Assert.All(parsed.Claims, claim => Assert.DoesNotContain("schemas.microsoft.com", claim.Type));
    }

    [Fact]
    public void Stamps_the_issuer_audience_and_a_unique_token_id()
    {
        var parsed = JwtBearerConfiguration.CreateTokenHandler().ReadJwtToken(Service().Issue(User()).Value);

        Assert.Equal("test-issuer", parsed.Issuer);
        Assert.Contains("test-audience", parsed.Audiences);
        Assert.NotEmpty(parsed.Claims.Single(c => c.Type == RegulatedAiClaims.TokenId).Value);
    }

    [Fact]
    public void Expires_after_the_configured_lifetime()
    {
        var token = Service().Issue(User());

        Assert.Equal(Now.AddMinutes(30), token.ExpiresAtUtc);
    }

    [Fact]
    public void Issues_a_distinct_token_id_each_time()
    {
        var handler = JwtBearerConfiguration.CreateTokenHandler();
        var service = Service();

        var first = handler.ReadJwtToken(service.Issue(User()).Value);
        var second = handler.ReadJwtToken(service.Issue(User()).Value);

        Assert.NotEqual(
            first.Claims.Single(c => c.Type == RegulatedAiClaims.TokenId).Value,
            second.Claims.Single(c => c.Type == RegulatedAiClaims.TokenId).Value);
    }

    /// <summary>
    /// Validated on the way out as well as in. An unknown tenant or role inside a *signed* token
    /// becomes trusted input everywhere downstream, so this is the cheapest place to stop it.
    /// </summary>
    [Fact]
    public void Refuses_to_issue_a_token_for_an_unknown_tenant() =>
        Assert.Throws<InvalidOperationException>(
            () => Service().Issue(User(tenantId: "tenant-does-not-exist")));

    [Fact]
    public void Refuses_to_issue_a_token_for_an_unknown_role() =>
        Assert.Throws<InvalidOperationException>(() => Service().Issue(User(role: "superuser")));
}

public sealed class JwtOptionsTests
{
    private static JwtOptions Valid() => new()
    {
        Issuer = "issuer",
        Audience = "audience",
        SigningKey = new string('k', 32),
        SeedUserPassword = "Passw0rd!",
        AccessTokenLifetimeMinutes = 30,
    };

    [Fact]
    public void Accepts_a_complete_configuration() => Valid().Validate();

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Requires_an_issuer(string issuer)
    {
        var options = Valid();
        options.Issuer = issuer;

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Requires_an_audience()
    {
        var options = Valid();
        options.Audience = string.Empty;

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Requires_a_seed_password_because_there_is_no_identity_provider()
    {
        var options = Valid();
        options.SeedUserPassword = string.Empty;

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    public void Rejects_a_signing_key_below_the_hs256_minimum(int keyLength)
    {
        var options = Valid();
        options.SigningKey = new string('k', keyLength);

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    /// <summary>
    /// Key policy is configurable, but not downwards past the algorithm's own requirement. A
    /// deployment that could configure its way under 256 bits could configure itself into
    /// forgeable tokens.
    /// </summary>
    [Fact]
    public void Configuration_cannot_lower_the_signing_key_floor()
    {
        var options = Valid();
        options.MinimumSigningKeyBytes = 1;
        options.SigningKey = new string('k', 16);

        Assert.Equal(
            JwtOptions.AbsoluteMinimumSigningKeyBytes, options.EffectiveMinimumSigningKeyBytes);

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Configuration_can_raise_the_signing_key_requirement()
    {
        var options = Valid();
        options.MinimumSigningKeyBytes = 64;

        Assert.Equal(64, options.EffectiveMinimumSigningKeyBytes);
        Assert.Throws<InvalidOperationException>(options.Validate);

        options.SigningKey = new string('k', 64);
        options.Validate();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(481)]
    public void Rejects_a_lifetime_outside_the_configured_bounds(int minutes)
    {
        var options = Valid();
        options.AccessTokenLifetimeMinutes = minutes;

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Honours_configured_lifetime_bounds()
    {
        var options = Valid();
        options.MinAccessTokenLifetimeMinutes = 5;
        options.MaxAccessTokenLifetimeMinutes = 10;
        options.AccessTokenLifetimeMinutes = 30;

        Assert.Throws<InvalidOperationException>(options.Validate);

        options.AccessTokenLifetimeMinutes = 7;
        options.Validate();
    }

    [Fact]
    public void Rejects_incoherent_lifetime_bounds()
    {
        var options = Valid();
        options.MinAccessTokenLifetimeMinutes = 60;
        options.MaxAccessTokenLifetimeMinutes = 30;

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Rejects_a_negative_clock_skew()
    {
        var options = Valid();
        options.ClockSkewSeconds = -1;

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    /// <summary>
    /// Zero by default: the framework's five-minute grace period means an expired token keeps
    /// working for five more minutes, which is not a trade this service needs to make.
    /// </summary>
    [Fact]
    public void Defaults_clock_skew_to_zero() => Assert.Equal(0, new JwtOptions().ClockSkewSeconds);
}
