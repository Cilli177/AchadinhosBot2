using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class CatalogOfferStore : ICatalogOfferStore
{
    private readonly string _dataDirectory;
    private readonly ICatalogOfferEnrichmentService? _enrichmentService;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public CatalogOfferStore(ICatalogOfferEnrichmentService? enrichmentService = null)
        : this(enrichmentService, null)
    {
    }

    public CatalogOfferStore(ICatalogOfferEnrichmentService? enrichmentService, string? dataDirectory)
    {
        _enrichmentService = enrichmentService;
        _dataDirectory = string.IsNullOrWhiteSpace(dataDirectory)
            ? FindPersistentDataRoot(AppContext.BaseDirectory)
            : dataDirectory;
    }

    [ActivatorUtilitiesConstructor]
    public CatalogOfferStore(
        ICatalogOfferEnrichmentService? enrichmentService,
        IConfiguration? configuration,
        IWebHostEnvironment? environment)
        : this(enrichmentService, ResolveDataDirectory(configuration, environment))
    {
    }

    public async Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
        => await SyncDraftsCoreAsync(drafts, requirePublishedForProd: true, cancellationToken);

    public async Task<CatalogSyncResult> SyncExplicitDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
        => await SyncDraftsCoreAsync(drafts, requirePublishedForProd: false, cancellationToken);

    private async Task<CatalogSyncResult> SyncDraftsCoreAsync(
        IReadOnlyList<InstagramPublishDraft> drafts,
        bool requirePublishedForProd,
        CancellationToken cancellationToken)
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
                var sourceDrafts = string.Equals(target, CatalogTargets.Dev, StringComparison.OrdinalIgnoreCase) || !requirePublishedForProd
                    ? providedDrafts
                    : published;
                var targetDrafts = sourceDrafts
                    .Where(d => CatalogTargets.Expand(d.CatalogTarget, d.SendToCatalog).Contains(target, StringComparer.OrdinalIgnoreCase))
                    .ToList();
                var result = await SyncTargetDatabaseAsync(db, targetDrafts, processedDraftIds, target, now, cancellationToken);

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

    private async Task<CatalogSyncResult> SyncTargetDatabaseAsync(
        CatalogDatabase db,
        IReadOnlyList<InstagramPublishDraft> drafts,
        HashSet<string> processedDraftIds,
        string target,
        DateTimeOffset now,
        CancellationToken ct)
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
            
            var images = ResolveImageUrls(draft);
            existing.ImageUrl = images.FirstOrDefault();
            existing.SecondaryImageUrls = images.Skip(1).ToList();
            
            existing.PostType = NormalizePostType(draft.PostType);
            existing.CatalogTarget = target;
            existing.Niche = ResolveNicheFromDraft(draft);
            existing.Active = true;
            existing.PublishedAt = draft.CreatedAt;
            existing.UpdatedAt = now;
            
            existing.PriceText = ExtractPriceText(draft.Caption);

            // Enrichment
            if (_enrichmentService != null)
            {
                var enrichment = await _enrichmentService.TryEnrichAsync(existing.OfferUrl, ct);
                if (enrichment != null)
                {
                    existing.IsLightningDeal = enrichment.IsLightningDeal;
                    existing.LightningDealExpiry = enrichment.LightningDealExpiry;
                    existing.CouponCode = enrichment.CouponCode;
                    existing.CouponDescription = enrichment.CouponDescription;
                    
                    if (!string.IsNullOrWhiteSpace(enrichment.CurrentPrice))
                    {
                        existing.PriceText = enrichment.CurrentPrice;
                    }
                }
            }
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

    public async Task<int> RefreshPricesAsync(CancellationToken cancellationToken)
    {
        if (_enrichmentService is null) return 0;

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var refreshed = 0;
            var now = DateTimeOffset.UtcNow;
            var standardCycleAge = now.AddHours(-12);

            foreach (var target in new[] { CatalogTargets.Prod, CatalogTargets.Dev })
            {
                var db = await ReadAsync(target, cancellationToken);
                var dueItems = db.Items
                    .Where(x => !string.IsNullOrWhiteSpace(x.OfferUrl) && IsDueForPriceCheck(x, now, standardCycleAge))
                    .ToList();
                var changed = false;

                foreach (var item in dueItems)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    var enrichment = await _enrichmentService.TryEnrichAsync(item.OfferUrl, cancellationToken);
                    // Trata como "sem preço" tanto retorno null quanto objeto com CurrentPrice vazio.
                    // O scraper pode retornar um objeto não-nulo mas sem conseguir extrair o preço.
                    var priceUnavailable = enrichment is null || string.IsNullOrWhiteSpace(enrichment.CurrentPrice);
                    if (priceUnavailable)
                    {
                        item.PriceEnrichFailCount++;
                        item.UpdatedAt = now;

                        if (item.PriceEnrichFailCount == 1)
                        {
                            // Primeira falha: remove do catálogo imediatamente, retry em 5 min
                            item.Active = false;
                            item.NextPriceCheckAt = now.AddMinutes(5);
                        }
                        else if (item.PriceEnrichFailCount == 2)
                        {
                            // Segunda falha (retry de 5 min): retry em 20 min
                            item.NextPriceCheckAt = now.AddMinutes(20);
                        }
                        else
                        {
                            // Terceira falha (30 min no total): entra no ciclo padrão de 12h
                            item.NextPriceCheckAt = null;
                        }

                        changed = true;
                        continue;
                    }

                    // Preço voltou: reativa se estava desativado por falha de preço
                    if (enrichment is not null && !item.Active && item.PriceEnrichFailCount > 0)
                    {
                        item.Active = true;
                    }

                    item.PriceEnrichFailCount = 0;
                    item.NextPriceCheckAt = null;
                    item.IsLightningDeal = enrichment.IsLightningDeal;
                    item.LightningDealExpiry = enrichment.LightningDealExpiry;
                    item.CouponCode = enrichment.CouponCode;
                    item.CouponDescription = enrichment.CouponDescription;

                    if (!string.IsNullOrWhiteSpace(enrichment.CurrentPrice))
                    {
                        item.PriceText = enrichment.CurrentPrice;
                    }

                    item.UpdatedAt = now;
                    changed = true;
                    refreshed++;
                }

                if (changed)
                {
                    await WriteAsync(target, db, cancellationToken);
                }
            }

            return refreshed;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<int> RefreshMissingPricesAsync(int maxItems, CancellationToken cancellationToken)
    {
        if (_enrichmentService is null) return 0;

        var safeLimit = Math.Clamp(maxItems, 1, 200);

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var refreshed = 0;
            var now = DateTimeOffset.UtcNow;

            foreach (var target in new[] { CatalogTargets.Prod, CatalogTargets.Dev })
            {
                var db = await ReadAsync(target, cancellationToken);
                var missingPriceItems = db.Items
                    .Where(x => x.Active &&
                                !string.IsNullOrWhiteSpace(x.OfferUrl) &&
                                HasUnavailablePriceText(x.PriceText))
                    .OrderBy(x => x.UpdatedAt)
                    .Take(safeLimit)
                    .ToList();

                if (missingPriceItems.Count == 0)
                {
                    continue;
                }

                var changed = false;
                foreach (var item in missingPriceItems)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    var enrichment = await _enrichmentService.TryEnrichAsync(item.OfferUrl, cancellationToken);
                    if (enrichment is null || string.IsNullOrWhiteSpace(enrichment.CurrentPrice))
                    {
                        item.PriceEnrichFailCount++;
                        item.UpdatedAt = now;
                        changed = true;
                        continue;
                    }

                    item.PriceText = enrichment.CurrentPrice;
                    item.IsLightningDeal = enrichment.IsLightningDeal;
                    item.LightningDealExpiry = enrichment.LightningDealExpiry;
                    item.CouponCode = enrichment.CouponCode;
                    item.CouponDescription = enrichment.CouponDescription;
                    item.PriceEnrichFailCount = 0;
                    item.NextPriceCheckAt = null;
                    item.UpdatedAt = now;
                    changed = true;
                    refreshed++;
                }

                if (changed)
                {
                    await WriteAsync(target, db, cancellationToken);
                }
            }

            return refreshed;
        }
        finally
        {
            _mutex.Release();
        }
    }

    /// <summary>
    /// Determina se um item está pronto para verificação de preço neste tick do worker.
    /// Lógica: retry rápido (5 min / 20 min) ou ciclo padrão de 12h.
    /// </summary>
    private static bool IsDueForPriceCheck(CatalogOfferItem item, DateTimeOffset now, DateTimeOffset standardCycleAge)
    {
        // Retry agendado (5 min ou 20 min após falha)
        if (item.NextPriceCheckAt.HasValue)
            return item.NextPriceCheckAt.Value <= now;

        // Desativado por remoção de draft (PriceEnrichFailCount = 0, Active = false): não tentar reativar
        if (!item.Active && item.PriceEnrichFailCount == 0)
            return false;

        // Ciclo padrão de 12h: itens ativos ou em modo de falha prolongada (>= 3 tentativas)
        return item.UpdatedAt <= standardCycleAge;
    }

    private static bool HasUnavailablePriceText(string? priceText)
    {
        if (string.IsNullOrWhiteSpace(priceText))
        {
            return true;
        }

        var normalized = priceText.Trim();
        if (normalized.Length == 0)
        {
            return true;
        }

        return normalized.Contains("indispon", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("consulta", StringComparison.OrdinalIgnoreCase);
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
        var normalizedTarget = CatalogTargets.Normalize(target, CatalogTargets.Prod);
        var path = ResolveReadPath(normalizedTarget);
        if (string.IsNullOrWhiteSpace(path))
        {
            return await RecoverFromBackupAsync(normalizedTarget, cancellationToken) ?? new CatalogDatabase();
        }

        var db = await TryReadDatabaseAsync(path, cancellationToken);
        if (db is null)
        {
            return await RecoverFromBackupAsync(normalizedTarget, cancellationToken) ?? new CatalogDatabase();
        }

        if (db.Items.Count == 0)
        {
            var recovered = await RecoverFromBackupAsync(normalizedTarget, cancellationToken);
            if (recovered is not null && recovered.Items.Count > 0)
            {
                return recovered;
            }
        }

        foreach (var item in db.Items)
        {
            item.CatalogTarget = CatalogTargets.Normalize(item.CatalogTarget, normalizedTarget);
        }

        if (string.Equals(normalizedTarget, CatalogTargets.Prod, StringComparison.OrdinalIgnoreCase))
        {
            var legacyPath = ResolveLegacyPath();
            var legacyDb = await TryReadDatabaseAsync(legacyPath, cancellationToken);
            if (ShouldMergeLegacyProd(db, legacyDb))
            {
                db = MergeProdWithLegacy(db, legacyDb!);
            }
        }

        return db;
    }

    private static string ResolveDataDirectory(IConfiguration? configuration, IWebHostEnvironment? environment)
    {
        var configuredPath =
            configuration?["Catalog:DataDirectory"] ??
            configuration?["CatalogOfferStore:DataDirectory"] ??
            configuration?["CATALOG_DATA_DIRECTORY"] ??
            configuration?["CATALOGOFFERS_DATA_DIRECTORY"];

        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return Path.IsPathRooted(configuredPath)
                ? configuredPath
                : Path.GetFullPath(Path.Combine(environment?.ContentRootPath ?? AppContext.BaseDirectory, configuredPath));
        }

        return FindPersistentDataRoot(environment?.ContentRootPath ?? AppContext.BaseDirectory);
    }

    private static string FindPersistentDataRoot(string contentRootPath)
    {
        foreach (var candidate in new[]
        {
            @"D:\Achadinhos\data",
            @"C:\Achadinhos\data"
        })
        {
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        foreach (var startPath in new[] { contentRootPath, AppContext.BaseDirectory })
        {
            var directory = new DirectoryInfo(startPath);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "AchadinhosBot2.sln")) ||
                    Directory.Exists(Path.Combine(directory.FullName, ".git")) ||
                    Directory.Exists(Path.Combine(directory.FullName, ".runtime")))
                {
                    return Path.Combine(directory.FullName, "data");
                }

                directory = directory.Parent;
            }
        }

        return Path.Combine(contentRootPath, "data");
    }

    private string? ResolveReadPath(string target)
    {
        var normalizedTarget = CatalogTargets.Normalize(target, CatalogTargets.Prod);
        var primaryPath = ResolvePath(normalizedTarget);
        var legacyPath = ResolveLegacyPath();

        if (File.Exists(primaryPath))
        {
            var primaryInfo = new FileInfo(primaryPath);
            if (primaryInfo.Length > 0)
            {
                return primaryPath;
            }

            if (string.Equals(normalizedTarget, CatalogTargets.Prod, StringComparison.OrdinalIgnoreCase) &&
                File.Exists(legacyPath) &&
                new FileInfo(legacyPath).Length > 0)
            {
                return legacyPath;
            }

            return primaryPath;
        }

        if (string.Equals(normalizedTarget, CatalogTargets.Prod, StringComparison.OrdinalIgnoreCase) &&
            File.Exists(legacyPath))
        {
            return legacyPath;
        }

        return null;
    }

    private async Task WriteAsync(string target, CatalogDatabase db, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_dataDirectory);
        var normalizedTarget = CatalogTargets.Normalize(target, CatalogTargets.Prod);
        var path = ResolvePath(normalizedTarget);
        await BackupCurrentFileAsync(path, normalizedTarget, cancellationToken);
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, db, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);

        if (string.Equals(normalizedTarget, CatalogTargets.Prod, StringComparison.OrdinalIgnoreCase))
        {
            var legacyPath = ResolveLegacyPath();
            await using var legacyStream = File.Create(legacyPath);
            await JsonSerializer.SerializeAsync(legacyStream, db, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
        }
    }

    private string ResolvePath(string target)
        => Path.Combine(_dataDirectory, $"catalog-offers.{CatalogTargets.Normalize(target, CatalogTargets.Prod)}.json");

    private string ResolveLegacyPath()
        => Path.Combine(_dataDirectory, "catalog-offers.json");

    private async Task<CatalogDatabase?> TryReadDatabaseAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var fileInfo = new FileInfo(path);
        if (fileInfo.Length == 0)
        {
            return new CatalogDatabase();
        }

        try
        {
            await using var stream = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync<CatalogDatabase>(stream, cancellationToken: cancellationToken) ?? new CatalogDatabase();
        }
        catch (JsonException)
        {
            return new CatalogDatabase();
        }
    }

    private async Task<CatalogDatabase?> RecoverFromBackupAsync(string target, CancellationToken cancellationToken)
    {
        var backupPath = FindLatestBackupPath(target);
        if (string.IsNullOrWhiteSpace(backupPath))
        {
            return null;
        }

        try
        {
            await using var stream = File.OpenRead(backupPath);
            var db = await JsonSerializer.DeserializeAsync<CatalogDatabase>(stream, cancellationToken: cancellationToken) ?? new CatalogDatabase();
            foreach (var item in db.Items)
            {
                item.CatalogTarget = CatalogTargets.Normalize(item.CatalogTarget, target);
            }

            var currentPath = ResolvePath(target);
            Directory.CreateDirectory(_dataDirectory);
            await using (var output = File.Create(currentPath))
            {
                await JsonSerializer.SerializeAsync(output, db, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
            }

            if (string.Equals(CatalogTargets.Normalize(target, CatalogTargets.Prod), CatalogTargets.Prod, StringComparison.OrdinalIgnoreCase))
            {
                var legacyPath = ResolveLegacyPath();
                await using var legacyStream = File.Create(legacyPath);
                await JsonSerializer.SerializeAsync(legacyStream, db, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
            }

            return db;
        }
        catch
        {
            return null;
        }
    }

    private string? FindLatestBackupPath(string target)
    {
        var normalizedTarget = CatalogTargets.Normalize(target, CatalogTargets.Prod);
        var versionsDirectory = Path.Combine(_dataDirectory, "versions");
        var candidates = new List<string>();

        if (Directory.Exists(versionsDirectory))
        {
            candidates.AddRange(Directory.EnumerateFiles(versionsDirectory, $"catalog-offers.{normalizedTarget}*.json.bak", SearchOption.TopDirectoryOnly));
        }

        candidates.AddRange(Directory.EnumerateFiles(_dataDirectory, $"catalog-offers.{normalizedTarget}*.json.bak*", SearchOption.TopDirectoryOnly));

        return candidates
            .Select(path => new FileInfo(path))
            .Where(info => info.Exists && info.Length > 0)
            .OrderByDescending(info => info.LastWriteTimeUtc)
            .Select(info => info.FullName)
            .FirstOrDefault();
    }

    private static bool ShouldMergeLegacyProd(CatalogDatabase primaryDb, CatalogDatabase? legacyDb)
    {
        if (legacyDb is null || legacyDb.Items.Count == 0)
        {
            return false;
        }

        return legacyDb.Items.Count > primaryDb.Items.Count ||
               legacyDb.Items.Count(x => x.Active) > primaryDb.Items.Count(x => x.Active);
    }

    private static CatalogDatabase MergeProdWithLegacy(CatalogDatabase primaryDb, CatalogDatabase legacyDb)
    {
        var merged = CloneDatabase(primaryDb);
        foreach (var legacyItem in legacyDb.Items)
        {
            legacyItem.CatalogTarget = CatalogTargets.Prod;
            var match = merged.Items.FirstOrDefault(item =>
                item.ItemNumber == legacyItem.ItemNumber ||
                (!string.IsNullOrWhiteSpace(item.DraftId) &&
                 !string.IsNullOrWhiteSpace(legacyItem.DraftId) &&
                 string.Equals(item.DraftId, legacyItem.DraftId, StringComparison.OrdinalIgnoreCase)));

            if (match is null)
            {
                merged.Items.Add(CloneItem(legacyItem, CatalogTargets.Prod));
                continue;
            }

            if (!match.Active && legacyItem.Active)
            {
                match.Active = true;
                match.UpdatedAt = legacyItem.UpdatedAt > match.UpdatedAt ? legacyItem.UpdatedAt : match.UpdatedAt;
            }

            if (string.IsNullOrWhiteSpace(match.Keyword) && !string.IsNullOrWhiteSpace(legacyItem.Keyword))
            {
                match.Keyword = legacyItem.Keyword;
            }

            if (string.IsNullOrWhiteSpace(match.ProductName) && !string.IsNullOrWhiteSpace(legacyItem.ProductName))
            {
                match.ProductName = legacyItem.ProductName;
            }

            if (string.IsNullOrWhiteSpace(match.Store) && !string.IsNullOrWhiteSpace(legacyItem.Store))
            {
                match.Store = legacyItem.Store;
            }

            if (string.IsNullOrWhiteSpace(match.OfferUrl) && !string.IsNullOrWhiteSpace(legacyItem.OfferUrl))
            {
                match.OfferUrl = legacyItem.OfferUrl;
            }

            if (string.IsNullOrWhiteSpace(match.ImageUrl) && !string.IsNullOrWhiteSpace(legacyItem.ImageUrl))
            {
                match.ImageUrl = legacyItem.ImageUrl;
            }
        }

        var maxNumber = merged.Items.Count == 0 ? 0 : merged.Items.Max(x => x.ItemNumber);
        if (merged.NextItemNumber <= maxNumber)
        {
            merged.NextItemNumber = maxNumber + 1;
        }

        return merged;
    }

    private static CatalogDatabase CloneDatabase(CatalogDatabase source)
    {
        return new CatalogDatabase
        {
            NextItemNumber = source.NextItemNumber,
            Items = source.Items
                .Select(item => CloneItem(item, item.CatalogTarget))
                .ToList()
        };
    }

    private static CatalogOfferItem CloneItem(CatalogOfferItem source, string target)
    {
        return new CatalogOfferItem
        {
            ItemNumber = source.ItemNumber,
            DraftId = source.DraftId,
            Keyword = source.Keyword,
            ProductName = source.ProductName,
            Store = source.Store,
            OfferUrl = source.OfferUrl,
            ImageUrl = source.ImageUrl,
            SecondaryImageUrls = source.SecondaryImageUrls?.ToList() ?? new List<string>(),
            PostType = source.PostType,
            CatalogTarget = CatalogTargets.Normalize(source.CatalogTarget, target),
            Niche = source.Niche,
            Active = source.Active,
            PublishedAt = source.PublishedAt,
            UpdatedAt = source.UpdatedAt,
            PriceText = source.PriceText,
            IsLightningDeal = source.IsLightningDeal,
            LightningDealExpiry = source.LightningDealExpiry,
            CouponCode = source.CouponCode,
            CouponDescription = source.CouponDescription
        };
    }

    private async Task BackupCurrentFileAsync(string path, string target, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var fileInfo = new FileInfo(path);
        if (fileInfo.Length == 0)
        {
            return;
        }

        var versionsDirectory = Path.Combine(_dataDirectory, "versions");
        Directory.CreateDirectory(versionsDirectory);
        var backupName = $"catalog-offers.{CatalogTargets.Normalize(target, CatalogTargets.Prod)}.{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.json.bak";
        var backupPath = Path.Combine(versionsDirectory, backupName);

        await using var source = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        await using var destination = File.Create(backupPath);
        await source.CopyToAsync(destination, cancellationToken);
    }

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
        if (!string.IsNullOrWhiteSpace(draft.OriginalOfferUrl) && !IsCatalogSelfUrl(draft.OriginalOfferUrl))
        {
            return draft.OriginalOfferUrl.Trim();
        }

        if (!string.IsNullOrWhiteSpace(draft.OfferUrl) && !IsCatalogSelfUrl(draft.OfferUrl))
        {
            return draft.OfferUrl.Trim();
        }

        var cta = draft.Ctas?
            .Select(x => x.Link)
            .FirstOrDefault(link => !string.IsNullOrWhiteSpace(link) && !IsCatalogSelfUrl(link));
        if (!string.IsNullOrWhiteSpace(cta))
        {
            return cta.Trim();
        }

        if (!string.IsNullOrWhiteSpace(draft.AutoReplyLink) && !IsCatalogSelfUrl(draft.AutoReplyLink))
        {
            return draft.AutoReplyLink.Trim();
        }

        if (!string.IsNullOrWhiteSpace(draft.Caption))
        {
            var match = Regex.Match(draft.Caption, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success && !IsCatalogSelfUrl(match.Value))
            {
                return match.Value.Trim();
            }
        }

        return BuildMarketplaceSearchUrl(ResolveStore(draft, draft.Caption ?? string.Empty), draft.ProductName);
    }

    private static string BuildMarketplaceSearchUrl(string? store, string? productName)
    {
        var query = (productName ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(query))
        {
            return string.Empty;
        }

        var encodedQuery = Uri.EscapeDataString(query);
        var normalizedStore = (store ?? string.Empty).Trim();

        if (normalizedStore.Contains("Shopee", StringComparison.OrdinalIgnoreCase))
        {
            return $"https://shopee.com.br/search?keyword={encodedQuery}";
        }

        if (normalizedStore.Contains("Mercado Livre", StringComparison.OrdinalIgnoreCase) ||
            normalizedStore.Contains("MercadoLivre", StringComparison.OrdinalIgnoreCase) ||
            normalizedStore.Contains("ML", StringComparison.OrdinalIgnoreCase))
        {
            return $"https://lista.mercadolivre.com.br/{encodedQuery}";
        }

        if (normalizedStore.Contains("Amazon", StringComparison.OrdinalIgnoreCase))
        {
            return $"https://www.amazon.com.br/s?k={encodedQuery}";
        }

        return $"https://www.google.com/search?q={encodedQuery}";
    }

    private static bool IsCatalogSelfUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return false;
        }

        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!string.Equals(uri.Host, "reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return uri.AbsolutePath.StartsWith("/catalogo", StringComparison.OrdinalIgnoreCase);
    }

    private static List<string> ResolveImageUrls(InstagramPublishDraft draft)
    {
        var urls = new List<string>();
        var selected = draft.SelectedImageIndexes ?? new List<int>();
        
        if (selected.Count > 0)
        {
            foreach (var idx in selected)
            {
                var adjustedIdx = idx - 1;
                if (adjustedIdx >= 0 && adjustedIdx < draft.ImageUrls.Count)
                {
                    var url = draft.ImageUrls[adjustedIdx];
                    if (!string.IsNullOrWhiteSpace(url))
                    {
                        urls.Add(url);
                    }
                }
            }
        }
        else
        {
            urls.AddRange(draft.ImageUrls.Where(x => !string.IsNullOrWhiteSpace(x)));
        }

        return urls;
    }

    private static string? ResolveNicheFromDraft(InstagramPublishDraft draft)
    {
        var text = (draft.ProductName + " " + draft.Caption).ToLowerInvariant();
        
        if (text.Contains("eletronico") || text.Contains("smartphone") || text.Contains("celular") || text.Contains("laptop") || text.Contains("notebook"))
            return "eletronicos";
            
        if (text.Contains("casa") || text.Contains("cozinha") || text.Contains("decoracao") || text.Contains("moveis"))
            return "casa";
            
        if (text.Contains("beleza") || text.Contains("maquiagem") || text.Contains("perfume") || text.Contains("skin care"))
            return "beleza";
            
        if (text.Contains("gaming") || text.Contains("gamer") || text.Contains("jogo") || text.Contains("playstation") || text.Contains("xbox"))
            return "gaming";
            
        return null;
    }

    private static string NormalizePostType(string? postType)
    {
        var value = (postType ?? "feed").Trim().ToLowerInvariant();
        return value switch
        {
            "story" => "story",
            "stories" => "story",
            "reel" => "reel",
            "reels" => "reel",
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
