using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IChannelOfferCandidateStore
{
    Task UpsertManyAsync(IEnumerable<ChannelOfferCandidate> candidates, CancellationToken cancellationToken);
    Task<ChannelOfferCandidate?> GetAsync(string sourceChannel, string messageId, CancellationToken cancellationToken);
}
