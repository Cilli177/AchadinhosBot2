using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Tests;

public sealed class OfferAnomalyDetectorTests
{
    [Fact]
    public async Task DetectAsync_FlagsInvalidAndDuplicateOffers()
    {
        var store = new StubCatalogStore(
            new CatalogOfferItem { Id = "1", Active = true, OfferUrl = "invalid-url", ProductName = "A", PriceText = null, CatalogTarget = CatalogTargets.Prod },
            new CatalogOfferItem { Id = "2", Active = true, OfferUrl = "https://example.com/p", ProductName = "Produto bom", PriceText = "R$ 10,00", CatalogTarget = CatalogTargets.Prod },
            new CatalogOfferItem { Id = "3", Active = true, OfferUrl = "https://example.com/p", ProductName = "Produto bom 2", PriceText = "R$ 12,00", CatalogTarget = CatalogTargets.Dev });
        var detector = new OfferAnomalyDetector(store);

        var result = await detector.DetectAsync(CancellationToken.None);

        Assert.NotEmpty(result);
        Assert.Contains(result, x => x.OfferId == "1");
        Assert.Contains(result, x => x.Reasons.Any(r => r.Contains("Duplicidade", StringComparison.OrdinalIgnoreCase)));
    }

    private sealed class StubCatalogStore : ICatalogOfferStore
    {
        private readonly IReadOnlyList<CatalogOfferItem> _items;

        public StubCatalogStore(params CatalogOfferItem[] items)
        {
            _items = items;
        }

        public Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
            => Task.FromResult(new CatalogSyncResult());

        public Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult(_items);

        public Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<CatalogOfferItem?>(null);

        public Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<IReadOnlyDictionary<string, CatalogOfferItem>>(new Dictionary<string, CatalogOfferItem>());

        public Task<IReadOnlyList<VersionSnapshotInfo>> ListVersionsAsync(string catalogTarget, int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<VersionSnapshotInfo>>(Array.Empty<VersionSnapshotInfo>());

        public Task<VersionSnapshotInfo?> GetCurrentVersionAsync(string catalogTarget, CancellationToken cancellationToken)
            => Task.FromResult<VersionSnapshotInfo?>(null);

        public Task RestoreVersionAsync(string catalogTarget, string versionId, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }
}
