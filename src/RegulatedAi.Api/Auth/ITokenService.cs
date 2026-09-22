using RegulatedAi.Core.Data;

namespace RegulatedAi.Api.Auth;

public sealed record AccessToken(string Value, DateTimeOffset ExpiresAtUtc);

/// <summary>Issues the bearer tokens that carry tenant and role.</summary>
public interface ITokenService
{
    /// <exception cref="InvalidOperationException">
    /// The account names a tenant or role this service does not recognise. Refusing to mint the
    /// token is the point: an unknown tenant or role in a *signed* token would be trusted by
    /// everything downstream.
    /// </exception>
    AccessToken Issue(UserAccount user);
}
