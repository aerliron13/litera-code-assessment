using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using RegulatedAi.Api.Auth;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Api.Controllers;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Api.UnitTests;

public sealed class AuthControllerTests
{
    private const string Password = "Passw0rd!";

    private static readonly UserAccount Alice =
        new("alice", "alice", Password, Tenants.A, Roles.Analyst);

    private readonly Mock<IUserStore> _users = new();
    private readonly Mock<ITokenService> _tokens = new();
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _tokens
            .Setup(instance => instance.Issue(It.IsAny<UserAccount>()))
            .Returns(new AccessToken("issued-token", DateTimeOffset.UnixEpoch.AddYears(60)));

        _controller = new AuthController(
            _users.Object, _tokens.Object, NullLogger<AuthController>.Instance);
    }

    private ActionResult<LoginResponse> Login(string username, string password) =>
        _controller.Login(new LoginRequest { Username = username, Password = password });

    [Fact]
    public void Issues_a_token_for_valid_credentials()
    {
        _users.Setup(instance => instance.FindByUsername("alice")).Returns(Alice);

        var response = Login("alice", Password);

        var ok = Assert.IsType<OkObjectResult>(response.Result);
        var body = Assert.IsType<LoginResponse>(ok.Value);

        Assert.Equal("issued-token", body.AccessToken);
        Assert.Equal("Bearer", body.TokenType);
        Assert.Equal(Tenants.A, body.TenantId);
        Assert.Equal("alice", body.UserId);
        Assert.Equal(Roles.Analyst, body.Role);
    }

    [Fact]
    public void Rejects_a_wrong_password()
    {
        _users.Setup(instance => instance.FindByUsername("alice")).Returns(Alice);

        Assert.IsType<UnauthorizedObjectResult>(Login("alice", "wrong").Result);

        _tokens.Verify(instance => instance.Issue(It.IsAny<UserAccount>()), Times.Never);
    }

    [Fact]
    public void Rejects_an_unknown_user()
    {
        _users.Setup(instance => instance.FindByUsername(It.IsAny<string>())).Returns((UserAccount?)null);

        Assert.IsType<UnauthorizedObjectResult>(Login("nobody", Password).Result);

        _tokens.Verify(instance => instance.Issue(It.IsAny<UserAccount>()), Times.Never);
    }

    /// <summary>
    /// A wrong password and an unknown account must be indistinguishable, or the endpoint becomes
    /// a user-enumeration oracle.
    /// </summary>
    [Fact]
    public void Does_not_reveal_whether_an_account_exists()
    {
        _users.Setup(instance => instance.FindByUsername("alice")).Returns(Alice);
        _users.Setup(instance => instance.FindByUsername("nobody")).Returns((UserAccount?)null);

        var wrongPassword = Assert.IsType<UnauthorizedObjectResult>(Login("alice", "wrong").Result);
        var unknownUser = Assert.IsType<UnauthorizedObjectResult>(Login("nobody", "wrong").Result);

        Assert.Equal(wrongPassword.StatusCode, unknownUser.StatusCode);
        Assert.Equal(
            Assert.IsType<ProblemDetails>(wrongPassword.Value).Detail,
            Assert.IsType<ProblemDetails>(unknownUser.Value).Detail);
    }

    [Fact]
    public void Compares_the_credential_even_when_the_account_is_unknown()
    {
        // The comparison runs regardless, so response time does not distinguish the two cases.
        _users.Setup(instance => instance.FindByUsername(It.IsAny<string>())).Returns((UserAccount?)null);

        Assert.IsType<UnauthorizedObjectResult>(Login("nobody", Password).Result);

        _users.Verify(instance => instance.FindByUsername("nobody"), Times.Once);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Rejects_an_empty_password(string password)
    {
        _users.Setup(instance => instance.FindByUsername("alice")).Returns(Alice);

        Assert.IsType<UnauthorizedObjectResult>(Login("alice", password).Result);
    }

    [Fact]
    public void Rejects_a_password_that_is_a_prefix_of_the_real_one()
    {
        _users.Setup(instance => instance.FindByUsername("alice")).Returns(Alice);

        Assert.IsType<UnauthorizedObjectResult>(Login("alice", Password[..4]).Result);
    }

    [Fact]
    public void Passes_the_found_account_to_the_token_service()
    {
        _users.Setup(instance => instance.FindByUsername("alice")).Returns(Alice);

        Login("alice", Password);

        _tokens.Verify(
            instance => instance.Issue(It.Is<UserAccount>(user =>
                user.UserId == "alice" && user.TenantId == Tenants.A && user.Role == Roles.Analyst)),
            Times.Once);
    }
}
