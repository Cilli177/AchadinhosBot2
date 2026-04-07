using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ICatalogOfferStore
{
    Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken);
    Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null);
    Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null);
    Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null);
    Task<IReadOnlyList<VersionSnapshotInfo>> ListVersionsAsync(string catalogTarget, int limit, CancellationToken cancellationToken);
    Task<VersionSnapshotInfo?> GetCurrentVersionAsync(string catalogTarget, CancellationToken cancellationToken);
    Task RestoreVersionAsync(string catalogTarget, string versionId, CancellationToken cancellationToken);
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
