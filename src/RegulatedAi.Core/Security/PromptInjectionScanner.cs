using System.Text.RegularExpressions;

namespace RegulatedAi.Core.Security;

/// <summary>
/// Pattern-based screening for instruction-like content in retrieved documents.
/// </summary>
/// <remarks>
/// Every pattern carries a match timeout. Regex over attacker-influenced input without one is a
/// denial-of-service primitive, and evidence text is exactly that kind of input.
/// </remarks>
public sealed class PromptInjectionScanner : IPromptInjectionScanner
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    private const RegexOptions Options =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    /// <summary>
    /// Named patterns. Names are what reach the audit trail and the response, so they are written
    /// to be meaningful to whoever reads them during an incident.
    /// </summary>
    private static readonly (string Name, Regex Pattern)[] Patterns =
    {
        ("ignore-previous-instructions", new Regex(
            @"\b(ignore|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)?\s*instructions?\b",
            Options, MatchTimeout)),

        ("disregard-policy", new Regex(
            @"\bdisregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior)?\s*(instructions?|rules?|polic(y|ies)|guidance)\b",
            Options, MatchTimeout)),

        ("instruction-to-approve", new Regex(
            @"\b(approve|mark|authorise|authorize)\b[^.!?]{0,60}\b(immediately|now|approved|without\s+review)\b",
            Options, MatchTimeout)),

        ("no-further-review", new Regex(
            @"\bno\s+(further|additional|human)\s+(review|approval)\s+(is\s+)?(needed|required|necessary)\b",
            Options, MatchTimeout)),

        ("override-controls", new Regex(
            @"\b(override|bypass|skip|suppress)\s+(the\s+|any\s+)?(approval|review|control|polic(y|ies)|guardrail|gate)s?\b",
            Options, MatchTimeout)),

        ("addressed-to-the-model", new Regex(
            @"\b(note|instructions?|message|memo)\s+(for|to)\s+(the\s+)?(ai|assistant|reviewer|model|llm|agent)\b",
            Options, MatchTimeout)),

        ("system-prompt-reference", new Regex(
            @"\b(system\s+prompt|developer\s+message|you\s+are\s+an?\s+(ai|assistant|language\s+model))\b",
            Options, MatchTimeout)),
    };

    public InjectionScanResult Scan(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return InjectionScanResult.Clean;
        }

        var matched = new List<string>();

        foreach (var (name, pattern) in Patterns)
        {
            try
            {
                if (pattern.IsMatch(text))
                {
                    matched.Add(name);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Fail closed. Content we could not finish screening is treated as suspicious
                // rather than waved through, and the timeout itself is reported.
                matched.Add($"{name}-scan-timeout");
            }
        }

        return matched.Count == 0
            ? InjectionScanResult.Clean
            : new InjectionScanResult(true, matched);
    }
}
