using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class CatalogOfferStore : ICatalogOfferStore
{
    private readonly string _dataDirectory;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public CatalogOfferStore()
    {
        _dataDirectory = Path.Combine(AppContext.BaseDirectory, "data");
    }

    public async Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var aggregate = new CatalogSyncResult { SyncedAt = now };
            var providedDrafts = (drafts ?? Array.Empty<InstagramPublishDraft>()).ToList();
            var published = providedDrafts
                .Where(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
                .OrderBy(d => d.CreatedAt)
                .ToList();
            var processedDraftIds = new HashSet<string>(
                providedDrafts
                    .Where(x => !string.IsNullOrWhiteSpace(x.Id))
                    .Select(x => x.Id),
                StringComparer.OrdinalIgnoreCase);

            foreach (var target in new[] { CatalogTargets.Dev, CatalogTargets.Prod })
            {
                var db = await ReadAsync(target, cancellationToken);
                var targetDrafts = published
                    .Where(d => CatalogTargets.Expand(d.CatalogTarget, d.SendToCatalog).Contains(target, StringComparer.OrdinalIgnoreCase))
                    .ToList();
                var result = SyncTargetDatabase(db, targetDrafts, processedDraftIds, target, now);

                await WriteAsync(target, db, cancellationToken);

                aggregate.Created += result.Created;
                aggregate.Updated += result.Updated;
                aggregate.Deactivated += result.Deactivated;
                aggregate.TotalActive += result.TotalActive;
                aggregate.HighestItemNumber = Math.Max(aggregate.HighestItemNumber, result.HighestItemNumber);
            }

            return aggregate;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadItemsAsync(catalogTarget, cancellationToken);
            var query = (search ?? string.Empty).Trim();
            var filtered = items.Where(x => x.Active);
            if (!string.IsNullOrWhiteSpace(query))
            {
                if (int.TryParse(query, out var number))
                {
                    filtered = filtered.Where(x => x.ItemNumber == number || x.Keyword.Contains(query, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    filtered = filtered.Where(x =>
                        x.Keyword.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        x.ProductName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        x.Store.Contains(query, StringComparison.OrdinalIgnoreCase));
                }
            }

            return filtered
                .OrderByDescending(x => x.ItemNumber)
                .ThenBy(x => x.CatalogTarget)
                .Take(Math.Clamp(limit, 1, 500))
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadItemsAsync(catalogTarget, cancellationToken);
            var value = (query ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            if (int.TryParse(value, out var number))
            {
                return items
                    .Where(x => x.Active && x.ItemNumber == number)
                    .OrderByDescending(x => x.UpdatedAt)
                    .FirstOrDefault();
            }

            return items
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

    public async Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadItemsAsync(catalogTarget, cancellationToken);
            return items
                .Where(x => x.Active && !string.IsNullOrWhiteSpace(x.DraftId))
                .GroupBy(x => x.DraftId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    g => g.Key,
                    g => g.OrderByDescending(x => x.UpdatedAt).First(),
                    StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private CatalogSyncResult SyncTargetDatabase(
        CatalogDatabase db,
        IReadOnlyList<InstagramPublishDraft> drafts,
        HashSet<string> processedDraftIds,
        string target,
        DateTimeOffset now)
    {
        var created = 0;
        var updated = 0;
        var activeDraftIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var draft in drafts)
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
                    Keyword = BuildKeyword(draft, number),
                    CatalogTarget = target
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
            existing.CatalogTarget = target;
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
            if (item.Active &&
                processedDraftIds.Contains(item.DraftId) &&
                !activeDraftIds.Contains(item.DraftId))
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

    private async Task<List<CatalogOfferItem>> ReadItemsAsync(string? catalogTarget, CancellationToken cancellationToken)
    {
        var targets = ResolveReadableTargets(catalogTarget);
        var items = new List<CatalogOfferItem>();
        foreach (var target in targets)
        {
            var db = await ReadAsync(target, cancellationToken);
            items.AddRange(db.Items.Select(item =>
            {
                item.CatalogTarget = CatalogTargets.Normalize(item.CatalogTarget, target);
                return item;
            }));
        }

        return items;
    }

    private async Task<CatalogDatabase> ReadAsync(string target, CancellationToken cancellationToken)
    {
        var path = ResolvePath(target);
        if (!File.Exists(path))
        {
            var legacyPath = ResolveLegacyPath();
            if (string.Equals(target, CatalogTargets.Prod, StringComparison.OrdinalIgnoreCase) && File.Exists(legacyPath))
            {
                path = legacyPath;
            }
            else
            {
                return new CatalogDatabase();
            }
        }

        await using var stream = File.OpenRead(path);
        var db = await JsonSerializer.DeserializeAsync<CatalogDatabase>(stream, cancellationToken: cancellationToken);
        db ??= new CatalogDatabase();
        foreach (var item in db.Items)
        {
            item.CatalogTarget = CatalogTargets.Normalize(item.CatalogTarget, target);
        }

        return db;
    }

    private async Task WriteAsync(string target, CatalogDatabase db, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_dataDirectory);
        var path = ResolvePath(target);
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, db, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
    }

    private string ResolvePath(string target)
        => Path.Combine(_dataDirectory, $"catalog-offers.{CatalogTargets.Normalize(target, CatalogTargets.Prod)}.json");

    private string ResolveLegacyPath()
        => Path.Combine(_dataDirectory, "catalog-offers.json");

    private static IReadOnlyList<string> ResolveReadableTargets(string? catalogTarget)
    {
        var normalized = CatalogTargets.Normalize(catalogTarget, CatalogTargets.Prod);
        return normalized switch
        {
            CatalogTargets.Dev => [CatalogTargets.Dev],
            CatalogTargets.Both => [CatalogTargets.Prod, CatalogTargets.Dev],
            _ => [CatalogTargets.Prod]
        };
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
