using System.Security.Cryptography;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public static class WhatsAppWebhookIdempotency
{
    public static bool TryBegin(
        IIdempotencyStore store,
        string? instanceName,
        string chatId,
        string? senderId,
        string? messageId,
        bool fromMe,
        string? rawPayloadJson,
        string? text)
    {
        var instance = string.IsNullOrWhiteSpace(instanceName) ? "default" : instanceName;
        if (!string.IsNullOrWhiteSpace(messageId))
        {
            return store.TryBegin($"wa-msg:{instance}:{chatId}:{messageId}", TimeSpan.FromHours(6));
        }

        var sender = string.IsNullOrWhiteSpace(senderId) ? "unknown" : senderId;
        var hash = ComputeStableHash(rawPayloadJson ?? text);
        return store.TryBegin($"wa-msg-fallback:{instance}:{chatId}:{sender}:{fromMe}:{hash}", TimeSpan.FromSeconds(45));
    }

    private static string ComputeStableHash(string? input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
