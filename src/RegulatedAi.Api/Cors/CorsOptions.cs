namespace RegulatedAi.Api.Cors;

/// <summary>
/// Cross-origin policy, bound from the <c>Cors</c> configuration section.
/// </summary>
/// <remarks>
/// <para>
/// There is no browser client in this exercise and nothing to whitelist, so the shipped
/// configuration allows <b>no</b> origins. That is the point: the policy is present, explicit and
/// deny-by-default, so enabling a front end later is a configuration change someone has to make
/// deliberately rather than a decision that gets made by whoever is debugging a CORS error at the
/// time.
/// </para>
/// <para>
/// The failure mode this guards against is specific. A blocked browser request produces an opaque
/// console error, and the fastest way to make it go away is <c>AllowAnyOrigin</c> — which, on an
/// API where the bearer token lives in the browser, hands every site the user visits the ability
/// to call this API with that token. Making the allowed origins a configuration list means the fix
/// for that error is to add one origin, not to open the door.
/// </para>
/// </remarks>
public sealed class CorsOptions
{
    public const string SectionName = "Cors";

    /// <summary>The name of the policy applied to every endpoint.</summary>
    public const string PolicyName = "RegulatedAiDefault";

    /// <summary>
    /// Exact origins permitted to call this API from a browser, scheme and port included
    /// (for example <c>https://compliance.example.com</c>). Empty means no browser origin is
    /// allowed, which is the shipped default.
    /// </summary>
    public string[] AllowedOrigins { get; set; } = Array.Empty<string>();

    /// <summary>Permitted methods. Empty means the ones this API actually exposes.</summary>
    public string[] AllowedMethods { get; set; } = Array.Empty<string>();

    /// <summary>Permitted request headers. Empty means <c>Authorization</c> and <c>Content-Type</c>.</summary>
    public string[] AllowedHeaders { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Whether the browser may send cookies or HTTP authentication with a cross-origin request.
    /// False here: this API authenticates with a bearer token supplied explicitly by the caller,
    /// so it has no need for ambient credentials — and ambient credentials are what makes CSRF
    /// possible in the first place.
    /// </summary>
    public bool AllowCredentials { get; set; }

    /// <summary>How long a browser may cache a preflight response, in seconds.</summary>
    public int PreflightMaxAgeSeconds { get; set; } = 600;

    /// <summary>The methods to permit, falling back to what this API exposes.</summary>
    public string[] EffectiveMethods => AllowedMethods.Length > 0
        ? AllowedMethods
        : new[] { "GET", "POST", "OPTIONS" };

    /// <summary>The headers to permit, falling back to the ones this API needs.</summary>
    public string[] EffectiveHeaders => AllowedHeaders.Length > 0
        ? AllowedHeaders
        : new[] { "Authorization", "Content-Type" };

    /// <summary>True when a browser origin is permitted at all.</summary>
    public bool IsEnabled => AllowedOrigins.Length > 0;

    /// <summary>
    /// Fails fast at startup on a misconfiguration.
    /// </summary>
    public void Validate()
    {
        foreach (var origin in AllowedOrigins)
        {
            if (string.IsNullOrWhiteSpace(origin))
            {
                throw new InvalidOperationException(
                    $"{SectionName}:{nameof(AllowedOrigins)} must not contain empty entries.");
            }

            // A wildcard is refused outright rather than quietly accepted. On an authenticated API
            // it is almost never what someone means, and it is exactly what gets pasted in to make
            // a CORS error go away.
            if (origin == "*")
            {
                throw new InvalidOperationException(
                    $"{SectionName}:{nameof(AllowedOrigins)} must not contain '*'. List each "
                    + "permitted origin explicitly.");
            }

            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new InvalidOperationException(
                    $"{SectionName}:{nameof(AllowedOrigins)} entry '{origin}' must be an absolute "
                    + "http or https origin, for example 'https://compliance.example.com'.");
            }

            // An origin is scheme + host + port. A trailing slash or a path means whoever wrote it
            // was thinking of a URL, and the browser will never match it.
            if (!string.IsNullOrEmpty(uri.AbsolutePath.TrimEnd('/')) || uri.AbsolutePath.Length > 1)
            {
                throw new InvalidOperationException(
                    $"{SectionName}:{nameof(AllowedOrigins)} entry '{origin}' must be an origin "
                    + "with no path or trailing slash.");
            }
        }

        if (PreflightMaxAgeSeconds < 0)
        {
            throw new InvalidOperationException(
                $"{SectionName}:{nameof(PreflightMaxAgeSeconds)} must not be negative.");
        }
    }
}
