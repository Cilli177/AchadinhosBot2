using AchadinhosBot.Next.Domain.PriceWatch;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IPriceWatchStore
{
    Task<IReadOnlyList<PriceWatchItem>> ListAsync(CancellationToken cancellationToken, string? status = null, string? contactJid = null);
    Task<IReadOnlyList<PriceWatchItem>> ListDueAsync(DateTimeOffset now, int limit, CancellationToken cancellationToken);
    Task<PriceWatchItem?> GetAsync(string id, CancellationToken cancellationToken);
    Task SaveAsync(PriceWatchItem item, CancellationToken cancellationToken);
    Task UpdateAsync(PriceWatchItem item, CancellationToken cancellationToken);
    Task<int> PauseByContactAsync(string contactJid, CancellationToken cancellationToken);
    Task<IReadOnlyList<PriceWatchReviewItem>> ListReviewsAsync(CancellationToken cancellationToken, string? status = "pending");
    Task<PriceWatchReviewItem?> GetReviewAsync(string id, CancellationToken cancellationToken);
    Task SaveReviewAsync(PriceWatchReviewItem item, CancellationToken cancellationToken);
    Task UpdateReviewAsync(PriceWatchReviewItem item, CancellationToken cancellationToken);
}
