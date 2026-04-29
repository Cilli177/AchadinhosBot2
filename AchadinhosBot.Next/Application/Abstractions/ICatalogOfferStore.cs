using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ICatalogOfferStore
{
    Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken);
    Task<CatalogSyncResult> SyncExplicitDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
        => SyncFromPublishedDraftsAsync(drafts, cancellationToken);
    Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null);
    Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null);
    Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null);
    Task<int> RefreshPricesAsync(CancellationToken cancellationToken) => Task.FromResult(0);
    Task<int> RefreshMissingPricesAsync(int maxItems, CancellationToken cancellationToken) => Task.FromResult(0);
}

public interface ICatalogOfferEnrichmentService
{
    Task<CatalogOfferEnrichment?> TryEnrichAsync(string offerUrl, CancellationToken cancellationToken);
}

public sealed record CatalogOfferEnrichment(
    string? CurrentPrice,
    bool IsLightningDeal,
    DateTimeOffset? LightningDealExpiry,
    string? CouponCode,
    string? CouponDescription);
