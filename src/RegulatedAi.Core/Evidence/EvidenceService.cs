using RegulatedAi.Core.Contracts;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Security;

namespace RegulatedAi.Core.Evidence;

/// <inheritdoc cref="IEvidenceService"/>
public sealed class EvidenceService : IEvidenceService
{
    private const int MaxSnippetLength = 240;

    private static readonly char[] TokenSeparators =
        " \t\r\n.,;:!?()[]{}\"'/\\-".ToCharArray();

    private readonly IEvidenceStore _store;
    private readonly IPromptInjectionScanner _scanner;

    public EvidenceService(IEvidenceStore store, IPromptInjectionScanner scanner)
    {
        _store = store;
        _scanner = scanner;
    }

    public Task<IReadOnlyList<EvidenceSnippet>> SearchEvidenceAsync(
        string tenantId,
        string subjectId,
        string query,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException("A tenant id is required.", nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new ArgumentException("A subject id is required.", nameof(subjectId));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var queryTokens = Tokenize(query);

        // The store read is already tenant-scoped; the subject filter narrows within the tenant.
        var snippets = _store.GetForTenant(tenantId)
            .Where(document => document.AppliesToSubject(subjectId))
            .Select(document => new
            {
                Document = document,
                Score = Score(document, queryTokens),
            })
            .OrderByDescending(scored => scored.Score)
            .ThenBy(scored => scored.Document.DocumentId, StringComparer.Ordinal)
            .Select(scored => ToSnippet(scored.Document, queryTokens))
            .ToArray();

        return Task.FromResult<IReadOnlyList<EvidenceSnippet>>(snippets);
    }

    private EvidenceSnippet ToSnippet(EvidenceDocument document, IReadOnlyCollection<string> queryTokens)
    {
        // Screening happens at the retrieval boundary, so nothing downstream can receive an
        // unscreened snippet — the trust verdict travels with the content.
        var scan = _scanner.Scan(document.Text);

        return new EvidenceSnippet(
            document.DocumentId,
            document.SubjectId,
            document.Title,
            document.DocumentType,
            Snippetize(document.Text, queryTokens),
            document.EvidenceTags,
            document.ExpiresAtUtc,
            IsTrusted: !scan.IsSuspicious,
            scan.MatchedPatterns);
    }

    private static IReadOnlyCollection<string> Tokenize(string? text) =>
        string.IsNullOrWhiteSpace(text)
            ? Array.Empty<string>()
            : text.Split(TokenSeparators, StringSplitOptions.RemoveEmptyEntries)
                .Where(token => token.Length > 2)
                .Select(token => token.ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

    /// <summary>
    /// Naive token-overlap relevance, standing in for whatever a real deployment would use
    /// (BM25, a vector index). It only ever changes ordering, so its crudeness is not a
    /// correctness risk for the gate.
    /// </summary>
    private static int Score(EvidenceDocument document, IReadOnlyCollection<string> queryTokens)
    {
        if (queryTokens.Count == 0)
        {
            return 0;
        }

        var title = document.Title.ToLowerInvariant();
        var text = document.Text.ToLowerInvariant();

        var score = 0;
        foreach (var token in queryTokens)
        {
            // Title hits weigh more than body hits.
            if (title.Contains(token, StringComparison.Ordinal))
            {
                score += 3;
            }

            if (text.Contains(token, StringComparison.Ordinal))
            {
                score += 1;
            }
        }

        return score;
    }

    /// <summary>
    /// Extracts a window around the first query-term hit, falling back to the opening of the
    /// document. Bounded length keeps responses and audit context small.
    /// </summary>
    private static string Snippetize(string text, IReadOnlyCollection<string> queryTokens)
    {
        var normalized = text.Trim();

        if (normalized.Length <= MaxSnippetLength)
        {
            return normalized;
        }

        var anchor = 0;
        foreach (var token in queryTokens)
        {
            var index = normalized.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                anchor = index;
                break;
            }
        }

        // Back up a little so the window does not start mid-sentence.
        var start = Math.Max(0, anchor - 40);
        var length = Math.Min(MaxSnippetLength, normalized.Length - start);
        var window = normalized.Substring(start, length).Trim();

        var prefix = start > 0 ? "..." : string.Empty;
        var suffix = start + length < normalized.Length ? "..." : string.Empty;

        return string.Concat(prefix, window, suffix);
    }
}
