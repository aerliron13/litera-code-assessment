using Microsoft.AspNetCore.Cors.Infrastructure;

namespace RegulatedAi.Api.Cors;

/// <summary>
/// Builds the cross-origin policy from <see cref="CorsOptions"/>.
/// </summary>
/// <remarks>
/// Separated from <c>Program.cs</c> for the same reason as the token-validation configuration: a
/// policy that silently ends up more permissive than intended is worth asserting with a test
/// rather than reading back off a builder chain.
/// </remarks>
public static class CorsConfiguration
{
    public static void Apply(CorsPolicyBuilder builder, CorsOptions options)
    {
        // Named origins only. Note that there is no AllowAnyOrigin branch anywhere in this file —
        // an empty list yields a policy that matches no origin, which is the intended default.
        builder.WithOrigins(options.AllowedOrigins);
        builder.WithMethods(options.EffectiveMethods);
        builder.WithHeaders(options.EffectiveHeaders);
        builder.SetPreflightMaxAge(TimeSpan.FromSeconds(options.PreflightMaxAgeSeconds));

        if (options.AllowCredentials)
        {
            builder.AllowCredentials();
        }
        else
        {
            builder.DisallowCredentials();
        }
    }

    /// <summary>Builds the policy directly, for inspection and testing.</summary>
    public static CorsPolicy BuildPolicy(CorsOptions options)
    {
        var builder = new CorsPolicyBuilder();
        Apply(builder, options);
        return builder.Build();
    }
}
