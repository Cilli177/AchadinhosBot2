using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppOfferReasoner
{
    Task<WhatsAppOfferAiDecision?> ReasonAsync(
        WhatsAppOutboundLogEntry message,
        WhatsAppOfferSuggestion heuristicSuggestion,
        AutomationSettings settings,
        CancellationToken cancellationToken);
}
