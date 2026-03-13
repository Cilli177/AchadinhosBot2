using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOfferCurationAgentService
{
    Task<OfferCurationResult> CurateAsync(OfferCurationRequest request, CancellationToken cancellationToken);
}
