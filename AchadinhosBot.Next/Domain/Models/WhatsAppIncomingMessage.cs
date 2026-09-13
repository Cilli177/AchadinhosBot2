namespace AchadinhosBot.Next.Domain.Models;

public sealed record WhatsAppIncomingMessage(
    string ChatId,
    string? SenderId,
    string Text,
    bool FromMe,
    string? InstanceName,
    string? MessageId,
    bool HasMedia,
    string? MediaUrl,
    string? MediaBase64,
    string? MediaMimeType,
    string? MediaFileName,
    string? RawPayloadJson);
