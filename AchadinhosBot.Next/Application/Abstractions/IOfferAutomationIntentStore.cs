using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOfferAutomationIntentStore
{
    Task<OfferAutomationIntent> SaveAsync(OfferAutomationIntent intent, CancellationToken cancellationToken);
    Task<OfferAutomationIntent?> GetByNormalizationRunIdAsync(string normalizationRunId, CancellationToken cancellationToken);
}
