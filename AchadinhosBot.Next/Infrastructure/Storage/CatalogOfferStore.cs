using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class CatalogOfferStore : ICatalogOfferStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public CatalogOfferStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "catalog-offers.json");
    }

    public async Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var db = await ReadAsync(cancellationToken);
            var now = DateTimeOffset.UtcNow;
            var created = 0;
            var updated = 0;
            var activeDraftIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var published = (drafts ?? Array.Empty<InstagramPublishDraft>())
                .Where(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
                .OrderBy(d => d.CreatedAt)
                .ToList();

            foreach (var draft in published)
            {
                var offerUrl = ResolveOfferUrl(draft);
                if (string.IsNullOrWhiteSpace(offerUrl))
                {
                    continue;
                }

                activeDraftIds.Add(draft.Id);
                var existing = db.Items.FirstOrDefault(x => x.DraftId.Equals(draft.Id, StringComparison.OrdinalIgnoreCase));
                if (existing is null)
                {
                    var number = db.NextItemNumber <= 0 ? 1 : db.NextItemNumber;
                    db.NextItemNumber = number + 1;
                    existing = new CatalogOfferItem
                    {
                        ItemNumber = number,
                        DraftId = draft.Id,
                        Keyword = BuildKeyword(draft, number)
                    };
                    db.Items.Add(existing);
                    created++;
                }
                else
                {
                    updated++;
                }

                existing.ProductName = string.IsNullOrWhiteSpace(draft.ProductName) ? $"Item {existing.ItemNumber}" : draft.ProductName.Trim();
                existing.Store = ResolveStore(draft, offerUrl);
                existing.OfferUrl = offerUrl.Trim();
                existing.ImageUrl = ResolveImageUrl(draft);
                existing.PriceText = ExtractPriceText(draft.Caption);
                existing.PostType = NormalizePostType(draft.PostType);
                existing.Active = true;
                existing.PublishedAt = draft.CreatedAt;
                existing.UpdatedAt = now;
                if (string.IsNullOrWhiteSpace(existing.Keyword))
                {
                    existing.Keyword = BuildKeyword(draft, existing.ItemNumber);
                }
            }

            var deactivated = 0;
            foreach (var item in db.Items)
            {
                if (!activeDraftIds.Contains(item.DraftId) && item.Active)
                {
                    item.Active = false;
                    item.UpdatedAt = now;
                    deactivated++;
                }
            }

            var maxNumber = db.Items.Count == 0 ? 0 : db.Items.Max(x => x.ItemNumber);
            if (db.NextItemNumber <= maxNumber)
            {
                db.NextItemNumber = maxNumber + 1;
            }

            await WriteAsync(db, cancellationToken);
            return new CatalogSyncResult
            {
                Created = created,
                Updated = updated,
                Deactivated = deactivated,
                TotalActive = db.Items.Count(x => x.Active),
                HighestItemNumber = maxNumber,
                SyncedAt = now
            };
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var db = await ReadAsync(cancellationToken);
            var query = (search ?? string.Empty).Trim();
            var items = db.Items.Where(x => x.Active);
            if (!string.IsNullOrWhiteSpace(query))
            {
                if (int.TryParse(query, out var number))
                {
                    items = items.Where(x => x.ItemNumber == number || x.Keyword.Contains(query, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    items = items.Where(x =>
                        x.Keyword.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        x.ProductName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        x.Store.Contains(query, StringComparison.OrdinalIgnoreCase));
                }
            }

            return items
                .OrderByDescending(x => x.ItemNumber)
                .Take(Math.Clamp(limit, 1, 500))
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var db = await ReadAsync(cancellationToken);
            var value = (query ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            if (int.TryParse(value, out var number))
            {
                return db.Items
                    .Where(x => x.Active && x.ItemNumber == number)
                    .OrderByDescending(x => x.UpdatedAt)
                    .FirstOrDefault();
            }

            return db.Items
                .Where(x => x.Active)
                .OrderByDescending(x => x.UpdatedAt)
                .FirstOrDefault(x =>
                    x.Keyword.Equals(value, StringComparison.OrdinalIgnoreCase) ||
                    x.Keyword.Contains(value, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var db = await ReadAsync(cancellationToken);
            return db.Items
                .Where(x => x.Active && !string.IsNullOrWhiteSpace(x.DraftId))
                .ToDictionary(x => x.DraftId, x => x, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<CatalogDatabase> ReadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new CatalogDatabase();
        }

        await using var stream = File.OpenRead(_path);
        var db = await JsonSerializer.DeserializeAsync<CatalogDatabase>(stream, cancellationToken: cancellationToken);
        return db ?? new CatalogDatabase();
    }

    private async Task WriteAsync(CatalogDatabase db, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        await using var stream = File.Create(_path);
        await JsonSerializer.SerializeAsync(stream, db, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
    }

    private static string ResolveOfferUrl(InstagramPublishDraft draft)
    {
        var cta = draft.Ctas?.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.Link))?.Link;
        if (!string.IsNullOrWhiteSpace(cta))
        {
            return cta.Trim();
        }

        if (!string.IsNullOrWhiteSpace(draft.Caption))
        {
            var match = Regex.Match(draft.Caption, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success)
            {
                return match.Value.Trim();
            }
        }

        return string.Empty;
    }

    private static string? ResolveImageUrl(InstagramPublishDraft draft)
    {
        var selected = draft.SelectedImageIndexes ?? new List<int>();
        if (selected.Count > 0)
        {
            var first = selected[0] - 1;
            if (first >= 0 && first < draft.ImageUrls.Count)
            {
                return draft.ImageUrls[first];
            }
        }

        return draft.ImageUrls.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
    }

    private static string NormalizePostType(string? postType)
    {
        var value = (postType ?? "feed").Trim().ToLowerInvariant();
        return value switch
        {
            "story" => "story",
            "stories" => "story",
            _ => "feed"
        };
    }

    private static string BuildKeyword(InstagramPublishDraft draft, int itemNumber)
    {
        var ctaKeyword = draft.Ctas?.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.Keyword))?.Keyword;
        if (!string.IsNullOrWhiteSpace(ctaKeyword))
        {
            var normalized = Regex.Replace(ctaKeyword.Trim().ToUpperInvariant(), @"[^A-Z0-9]+", string.Empty, RegexOptions.CultureInvariant);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return normalized.Length > 20 ? normalized[..20] : normalized;
            }
        }

        return $"ITEM{itemNumber}";
    }

    private static string ResolveStore(InstagramPublishDraft draft, string offerUrl)
    {
        if (Uri.TryCreate(offerUrl, UriKind.Absolute, out var uri))
        {
            var host = uri.Host.ToLowerInvariant();
            if (host.Contains("amazon", StringComparison.Ordinal))
            {
                return "Amazon";
            }

            if (host.Contains("mercadolivre", StringComparison.Ordinal) || host.Contains("mercado-livre", StringComparison.Ordinal))
            {
                return "Mercado Livre";
            }

            if (host.Contains("shopee", StringComparison.Ordinal))
            {
                return "Shopee";
            }

            if (host.Contains("shein", StringComparison.Ordinal))
            {
                return "Shein";
            }
        }

        return "Loja";
    }

    private static string? ExtractPriceText(string? caption)
    {
        if (string.IsNullOrWhiteSpace(caption))
        {
            return null;
        }

        var match = Regex.Match(caption, @"R\$\s?\d{1,3}(?:\.\d{3})*(?:,\d{2})?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (match.Success)
        {
            return match.Value.Trim();
        }

        match = Regex.Match(caption, @"\b\d{1,4},\d{2}\b", RegexOptions.CultureInvariant);
        return match.Success ? $"R$ {match.Value.Trim()}" : null;
    }

    private sealed class CatalogDatabase
    {
        public int NextItemNumber { get; set; } = 1;
        public List<CatalogOfferItem> Items { get; set; } = new();
    }
}
