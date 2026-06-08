using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Tests;

public sealed class OfferNormalizationRoutingServiceTests
{
    [Fact]
    public async Task MaterializeAsync_CatalogTarget_CreatesAssistiveDraftsAndCatalogReference()
    {
        var publishStore = new InMemoryInstagramPublishStore();
        var catalogStore = new InMemoryCatalogOfferStore();
        var automationStore = new InMemoryOfferAutomationIntentStore();
        var service = new OfferNormalizationRoutingService(publishStore, catalogStore, automationStore);

        var run = BuildRun(OfferNormalizationTargets.Catalog);

        var updated = await service.MaterializeAsync(run, "tester", CancellationToken.None);

        Assert.Equal(OfferNormalizationTargets.Catalog, updated.AssistedDelivery?.Kind);
        Assert.Equal(OfferNormalizationStatuses.SentToCatalog, updated.AssistedDelivery?.Status);
        Assert.Equal(CatalogTargets.Dev, updated.AssistedDelivery?.TargetScope);
        Assert.NotEmpty(updated.AssistedDelivery?.ReferenceIds ?? []);
        Assert.Contains("catálogo", updated.AssistedDelivery?.Summary ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        var drafts = await publishStore.ListAsync(CancellationToken.None);
        Assert.Equal(2, drafts.Count);
        Assert.All(drafts, draft =>
        {
            Assert.True(draft.SendToCatalog);
            Assert.Equal(CatalogTargets.Dev, draft.CatalogTarget);
            Assert.True(draft.CatalogIntentLocked);
            Assert.Equal("draft", draft.Status);
            Assert.StartsWith("offer-normalization:", draft.SourceDataOrigin, StringComparison.OrdinalIgnoreCase);
        });

        Assert.Equal(1, catalogStore.SyncCalls);
        Assert.Equal(2, catalogStore.LastDrafts.Count);
    }

    [Fact]
    public async Task MaterializeAsync_QueueTarget_CreatesPersistentAutomationIntent()
    {
        var publishStore = new InMemoryInstagramPublishStore();
        var catalogStore = new InMemoryCatalogOfferStore();
        var automationStore = new InMemoryOfferAutomationIntentStore();
        var service = new OfferNormalizationRoutingService(publishStore, catalogStore, automationStore);

        var run = BuildRun(OfferNormalizationTargets.Queue);

        var updated = await service.MaterializeAsync(run, "tester", CancellationToken.None);

        Assert.Equal(OfferNormalizationTargets.Queue, updated.AssistedDelivery?.Kind);
        Assert.Equal(OfferNormalizationStatuses.QueuedForAutomation, updated.AssistedDelivery?.Status);
        Assert.Equal("audit", updated.AssistedDelivery?.TargetScope);
        Assert.Single(updated.AssistedDelivery?.ReferenceIds ?? []);

        var intent = await automationStore.GetByNormalizationRunIdAsync(run.Id, CancellationToken.None);
        Assert.NotNull(intent);
        Assert.Equal("prepared", intent!.Status);
        Assert.Equal(2, intent.OfferCount);
        Assert.Equal("tester", intent.Operator);
    }

    private static OfferNormalizationRun BuildRun(string target)
        => new()
        {
            Id = "run-001",
            CreatedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-3),
            UpdatedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-2),
            SourceType = "json",
            SelectedTarget = target,
            Status = OfferNormalizationStatuses.Normalized,
            Operator = "seed",
            Summary = "2 ofertas normalizadas.",
            NextStepHint = "Revise e encaminhe.",
            NormalizedOffers =
            [
                new CanonicalOfferRecord
                {
                    Source = "Shopee",
                    ProductName = "Fone Bluetooth",
                    ProductUrl = "https://example.com/fone",
                    OriginalPrice = 199.90m,
                    PromoPrice = 129.90m,
                    DiscountPercent = 35m,
                    StoreName = "Loja X",
                    Category = "Eletrônicos",
                    CommissionRaw = "12%",
                    ExtraFields = new Dictionary<string, string?> { ["image_url"] = "https://img.example.com/fone.jpg" }
                },
                new CanonicalOfferRecord
                {
                    Source = "Mercado Livre",
                    ProductName = "Cafeteira",
                    ProductUrl = "https://example.com/cafeteira",
                    OriginalPrice = 500m,
                    PromoPrice = 350m,
                    DiscountPercent = 30m,
                    StoreName = "Loja Oficial",
                    Category = "Casa",
                    CommissionRaw = "8%"
                }
            ]
        };

    private sealed class InMemoryInstagramPublishStore : IInstagramPublishStore
    {
        private readonly Dictionary<string, InstagramPublishDraft> _drafts = new(StringComparer.OrdinalIgnoreCase);

        public Task<IReadOnlyList<InstagramPublishDraft>> ListAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<InstagramPublishDraft>>(_drafts.Values.ToList());

        public Task<InstagramPublishDraft?> GetAsync(string id, CancellationToken ct)
        {
            _drafts.TryGetValue(id, out var draft);
            return Task.FromResult(draft);
        }

        public Task SaveAsync(InstagramPublishDraft draft, CancellationToken ct)
        {
            _drafts[draft.Id] = draft;
            return Task.CompletedTask;
        }

        public Task UpdateAsync(InstagramPublishDraft draft, CancellationToken ct)
        {
            _drafts[draft.Id] = draft;
            return Task.CompletedTask;
        }

        public Task ClearAsync(CancellationToken ct)
        {
            _drafts.Clear();
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryCatalogOfferStore : ICatalogOfferStore
    {
        public int SyncCalls { get; private set; }
        public IReadOnlyList<InstagramPublishDraft> LastDrafts { get; private set; } = [];

        public Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
        {
            SyncCalls++;
            LastDrafts = drafts.ToList();
            return Task.FromResult(new CatalogSyncResult
            {
                Created = drafts.Count,
                Updated = 0,
                TotalActive = drafts.Count
            });
        }

        public Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<IReadOnlyList<CatalogOfferItem>>([]);

        public Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<CatalogOfferItem?>(null);

        public Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<IReadOnlyDictionary<string, CatalogOfferItem>>(new Dictionary<string, CatalogOfferItem>());
    }

    private sealed class InMemoryOfferAutomationIntentStore : IOfferAutomationIntentStore
    {
        private readonly Dictionary<string, OfferAutomationIntent> _intents = new(StringComparer.OrdinalIgnoreCase);

        public Task<OfferAutomationIntent> SaveAsync(OfferAutomationIntent intent, CancellationToken cancellationToken)
        {
            if (_intents.TryGetValue(intent.NormalizationRunId, out var existing))
            {
                intent.Id = existing.Id;
                intent.CreatedAtUtc = existing.CreatedAtUtc;
            }

            intent.UpdatedAtUtc = DateTimeOffset.UtcNow;
            _intents[intent.NormalizationRunId] = intent;
            return Task.FromResult(intent);
        }

        public Task<OfferAutomationIntent?> GetByNormalizationRunIdAsync(string normalizationRunId, CancellationToken cancellationToken)
        {
            _intents.TryGetValue(normalizationRunId, out var intent);
            return Task.FromResult(intent);
        }
    }
}
