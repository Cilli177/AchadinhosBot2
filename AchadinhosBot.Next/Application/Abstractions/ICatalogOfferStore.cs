using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ICatalogOfferStore
{
    Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(
        IReadOnlyList<InstagramPublishDraft> drafts, 
        CancellationToken cancellationToken, 
        Infrastructure.ProductData.OfficialProductDataService? productDataService = null);
    Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null);
    Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null);
    Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null);
}
