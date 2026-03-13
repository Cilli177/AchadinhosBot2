using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppOfferScoutAgentService
{
    Task<WhatsAppOfferScoutResult> AnalyzeAsync(WhatsAppOfferScoutRequest request, CancellationToken cancellationToken);
}
