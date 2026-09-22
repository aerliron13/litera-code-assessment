using System.Text;

namespace RegulatedAi.Api.Auth;

/// <summary>
/// Token issuance and validation settings, bound from the <c>Jwt</c> configuration section.
/// </summary>
/// <remarks>
/// <b>Not a production authentication design.</b> The brief rules out a real authentication
/// provider, so this service signs its own tokens with a symmetric key from configuration. That
/// means the issuer and the verifier are the same process holding the same secret — fine for an
/// exercise, wrong for a real deployment, where tokens would come from an OIDC provider and be
/// validated against its published asymmetric keys. PRODUCTION_NOTES.md covers the migration.
/// </remarks>
public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    /// <summary>
    /// The floor that configuration cannot go below, regardless of
    /// <see cref="MinimumSigningKeyBytes"/>.
    /// </summary>
    /// <remarks>
    /// HS256 is defined over a 256-bit key, so a shorter one is not a tuning choice — it is a
    /// broken signature. Everything else about key policy is configurable; this bound is not,
    /// because a deployment that could configure its way under it would be able to configure
    /// itself into forgeable tokens.
    /// </remarks>
    public const int AbsoluteMinimumSigningKeyBytes = 32;

    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    /// <summary>Development-only symmetric signing key. Never a real secret; never committed as one.</summary>
    public string SigningKey { get; set; } = string.Empty;

    /// <summary>
    /// The shared password every seeded account uses. Exists only because there is no identity
    /// provider here.
    /// </summary>
    public string SeedUserPassword { get; set; } = string.Empty;

    // --- Configurable token policy -------------------------------------------------------------

    /// <summary>Lifetime stamped on issued tokens.</summary>
    public int AccessTokenLifetimeMinutes { get; set; } = 30;

    /// <summary>Required key material, in bytes. Clamped up to <see cref="AbsoluteMinimumSigningKeyBytes"/>.</summary>
    public int MinimumSigningKeyBytes { get; set; } = AbsoluteMinimumSigningKeyBytes;

    /// <summary>Shortest permitted value for <see cref="AccessTokenLifetimeMinutes"/>.</summary>
    public int MinAccessTokenLifetimeMinutes { get; set; } = 1;

    /// <summary>
    /// Longest permitted value for <see cref="AccessTokenLifetimeMinutes"/>. A ceiling exists so
    /// that "make login less annoying" cannot quietly become a year-long bearer token.
    /// </summary>
    public int MaxAccessTokenLifetimeMinutes { get; set; } = 480;

    /// <summary>
    /// Allowed clock skew when validating token lifetimes, in seconds. Defaults to zero: the
    /// framework default of five minutes means a revoked or expired token keeps working for five
    /// more minutes, which is not a trade this service needs to make.
    /// </summary>
    public int ClockSkewSeconds { get; set; }

    /// <summary>The effective key-length requirement, honouring the absolute floor.</summary>
    public int EffectiveMinimumSigningKeyBytes =>
        Math.Max(MinimumSigningKeyBytes, AbsoluteMinimumSigningKeyBytes);

    /// <summary>
    /// Fails fast at startup on a misconfiguration. A service that boots with a weak or missing
    /// signing key and only discovers it when a token is forged has failed in the wrong direction.
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new InvalidOperationException($"{SectionName}:{nameof(Issuer)} must be configured.");
        }

        if (string.IsNullOrWhiteSpace(Audience))
        {
            throw new InvalidOperationException($"{SectionName}:{nameof(Audience)} must be configured.");
        }

        if (string.IsNullOrWhiteSpace(SeedUserPassword))
        {
            throw new InvalidOperationException($"{SectionName}:{nameof(SeedUserPassword)} must be configured.");
        }

        if (MinAccessTokenLifetimeMinutes < 1)
        {
            throw new InvalidOperationException(
                $"{SectionName}:{nameof(MinAccessTokenLifetimeMinutes)} must be at least 1.");
        }

        if (MaxAccessTokenLifetimeMinutes < MinAccessTokenLifetimeMinutes)
        {
            throw new InvalidOperationException(
                $"{SectionName}:{nameof(MaxAccessTokenLifetimeMinutes)} must not be below "
                + $"{nameof(MinAccessTokenLifetimeMinutes)}.");
        }

        if (Encoding.UTF8.GetByteCount(SigningKey) < EffectiveMinimumSigningKeyBytes)
        {
            throw new InvalidOperationException(
                $"{SectionName}:{nameof(SigningKey)} must be at least {EffectiveMinimumSigningKeyBytes} "
                + "bytes.");
        }

        if (AccessTokenLifetimeMinutes < MinAccessTokenLifetimeMinutes
            || AccessTokenLifetimeMinutes > MaxAccessTokenLifetimeMinutes)
        {
            throw new InvalidOperationException(
                $"{SectionName}:{nameof(AccessTokenLifetimeMinutes)} must be between "
                + $"{MinAccessTokenLifetimeMinutes} and {MaxAccessTokenLifetimeMinutes}.");
        }

        if (ClockSkewSeconds < 0)
        {
            throw new InvalidOperationException(
                $"{SectionName}:{nameof(ClockSkewSeconds)} must not be negative.");
        }
    }
}
