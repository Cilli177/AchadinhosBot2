using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Compliance;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class MercadoLivreApprovalStore : IMercadoLivreApprovalStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public MercadoLivreApprovalStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "mercadolivre-pending.json");
    }

    public async Task AppendAsync(MercadoLivrePendingApproval entry, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            items.Add(entry);
            await WriteAllInternalAsync(items, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<MercadoLivrePendingApproval>> ListAsync(string? status, int limit, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            if (!string.IsNullOrWhiteSpace(status))
            {
                items = items
                    .Where(x => string.Equals(x.Status, status, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }

            return items
                .OrderByDescending(x => x.CreatedAt)
                .Take(Math.Clamp(limit, 1, 500))
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<MercadoLivrePendingApproval?> GetAsync(string id, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            return items.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlySet<string>> GetApprovedUrlsAsync(IReadOnlyCollection<string> urls, CancellationToken cancellationToken)
    {
        var requested = urls?
            .Select(NormalizeUrl)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (requested.Count == 0)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            var approved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var item in items)
            {
                if (!string.Equals(item.Status, "approved", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var candidates = new List<string>();
                if (item.ExtractedUrls is { Count: > 0 })
                {
                    candidates.AddRange(item.ExtractedUrls);
                }
                if (!string.IsNullOrWhiteSpace(item.OriginalText))
                {
                    candidates.AddRange(ExtractUrls(item.OriginalText));
                }
                if (!string.IsNullOrWhiteSpace(item.ConvertedText))
                {
                    candidates.AddRange(ExtractUrls(item.ConvertedText));
                }

                foreach (var candidate in candidates)
                {
                    var normalized = NormalizeUrl(candidate);
                    if (!string.IsNullOrWhiteSpace(normalized) && requested.Contains(normalized))
                    {
                        approved.Add(normalized);
                    }
                }
            }

            return approved;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<bool> DecideAsync(
        string id,
        string status,
        string reviewedBy,
        string? reviewNote,
        string? convertedText,
        int convertedLinks,
        CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            var entry = items.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                return false;
            }

            entry.Status = status;
            entry.ReviewedBy = reviewedBy;
            entry.ReviewedAt = DateTimeOffset.UtcNow;
            entry.ReviewNote = reviewNote;
            entry.ConvertedText = convertedText;
            entry.ConvertedLinks = convertedLinks;
            await WriteAllInternalAsync(items, cancellationToken);
            return true;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<MercadoLivrePendingApproval>> ReadAllInternalAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        if (!File.Exists(_path))
        {
            return new List<MercadoLivrePendingApproval>();
        }

        await using var stream = File.OpenRead(_path);
        var items = await JsonSerializer.DeserializeAsync<List<MercadoLivrePendingApproval>>(stream, cancellationToken: cancellationToken);
        return items ?? new List<MercadoLivrePendingApproval>();
    }

    private async Task WriteAllInternalAsync(List<MercadoLivrePendingApproval> items, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        await using var stream = File.Create(_path);
        await JsonSerializer.SerializeAsync(stream, items, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
    }

    private static IEnumerable<string> ExtractUrls(string text)
        => Regex.Matches(text ?? string.Empty, @"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
            .Select(m => m.Value.Trim());

    private static string? NormalizeUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var raw = value.Trim();
        var mlItemId = TryExtractMercadoLivreItemId(raw);
        if (!string.IsNullOrWhiteSpace(mlItemId))
        {
            // Canonical key for Mercado Livre approvals to ignore unstable query params and wrappers.
            return $"ml:{mlItemId}";
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var builder = new UriBuilder(uri)
        {
            Fragment = string.Empty
        };
        if ((builder.Scheme == Uri.UriSchemeHttp && builder.Port == 80) ||
            (builder.Scheme == Uri.UriSchemeHttps && builder.Port == 443))
        {
            builder.Port = -1;
        }

        var normalized = builder.Uri.ToString().TrimEnd('/');
        return normalized;
    }

    private static string? TryExtractMercadoLivreItemId(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        // Direct product URLs often contain MLB-123456 or MLB123456.
        var directMatch = Regex.Match(url, @"\bMLB[-_]?(\d{5,})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (directMatch.Success)
        {
            return $"MLB{directMatch.Groups[1].Value}";
        }

        // Mercado Livre anti-bot wrappers can carry the true URL in a "go" query param.
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var query = uri.Query;
            if (!string.IsNullOrWhiteSpace(query))
            {
                var goPrefix = "go=";
                var idx = query.IndexOf(goPrefix, StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    var start = idx + goPrefix.Length;
                    var end = query.IndexOf('&', start);
                    var encoded = end >= 0 ? query[start..end] : query[start..];
                    if (!string.IsNullOrWhiteSpace(encoded))
                    {
                        var decoded = Uri.UnescapeDataString(encoded);
                        var nestedMatch = Regex.Match(decoded, @"\bMLB[-_]?(\d{5,})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        if (nestedMatch.Success)
                        {
                            return $"MLB{nestedMatch.Groups[1].Value}";
                        }
                    }
                }
            }
        }

        return null;
    }
}
