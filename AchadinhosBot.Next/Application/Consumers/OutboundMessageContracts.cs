namespace AchadinhosBot.Next.Application.Consumers;

public sealed class SendWhatsAppMessageCommand
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeduplicationKey { get; set; } = string.Empty;
    public string Kind { get; set; } = "text";
    public string? InstanceName { get; set; }
    public string To { get; set; } = string.Empty;
    public string? Text { get; set; }
    public string? MediaUrl { get; set; }
    public string? MediaBase64 { get; set; }
    public string? MimeType { get; set; }
    public string? FileName { get; set; }
    public bool TextFallbackAllowed { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class SendTelegramMessageCommand
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeduplicationKey { get; set; } = string.Empty;
    public string? BotToken { get; set; }
    public long ChatId { get; set; }
    public string? Text { get; set; }
    public string? ImageUrl { get; set; }
    public bool TextFallbackAllowed { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
