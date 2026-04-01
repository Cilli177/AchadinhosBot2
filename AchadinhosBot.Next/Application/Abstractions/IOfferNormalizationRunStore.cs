using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOfferNormalizationRunStore
{
    Task<OfferNormalizationRun> SaveAsync(OfferNormalizationRun run, CancellationToken cancellationToken);
    Task<OfferNormalizationRun?> GetAsync(string id, CancellationToken cancellationToken);
    Task<IReadOnlyList<OfferNormalizationRun>> ListAsync(string? status, string? target, int limit, CancellationToken cancellationToken);
}
