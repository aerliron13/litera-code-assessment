namespace RegulatedAi.Core.Security;

/// <summary>The verdict on a piece of retrieved content.</summary>
/// <param name="MatchedPatterns">Pattern names only — never the offending text.</param>
public sealed record InjectionScanResult(bool IsSuspicious, IReadOnlyList<string> MatchedPatterns)
{
    public static InjectionScanResult Clean { get; } = new(false, Array.Empty<string>());
}

/// <summary>
/// Screens retrieved content for text that is trying to act as an instruction.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a detection aid, not the control.</b> The control is architectural: retrieved
/// content is only ever consulted as structured data (tags, expiry dates), and the risk decision
/// is made by deterministic code that cannot be talked out of its conclusion. A pattern scanner
/// is trivially evadable — by paraphrase, by another language, by encoding — so a design that
/// depended on it would be broken. Its job is to notice and quarantine the obvious cases, and to
/// make the attempt visible in the audit trail.
/// </para>
/// </remarks>
public interface IPromptInjectionScanner
{
    InjectionScanResult Scan(string text);
}
