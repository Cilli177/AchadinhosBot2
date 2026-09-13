using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

/// <summary>
/// Stable input boundary for the worker webhook. A single Evolution delivery can
/// carry either membership events or inbound messages; callers should not need
/// to understand the provider's JSON shapes.
/// </summary>
public sealed record BotConversorWebhookPayload(
    IReadOnlyList<WhatsAppIncomingMessage> Messages,
    IReadOnlyList<WhatsAppGroupMembershipEvent> MembershipEvents);

public static class BotConversorWebhookPayloadExtractor
{
    public static BotConversorWebhookPayload Extract(string body) => new(
        EvolutionIncomingMessageExtractor.Extract(body),
        EvolutionMembershipEventParser.Extract(body));
}
