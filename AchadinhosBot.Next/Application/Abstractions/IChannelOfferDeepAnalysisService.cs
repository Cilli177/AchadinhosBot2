using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IChannelOfferDeepAnalysisService
{
    Task<ChannelOfferDeepAnalysisResult> AnalyzeAsync(ChannelOfferDeepAnalysisRequest request, CancellationToken cancellationToken);
}
