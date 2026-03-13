namespace AchadinhosBot.Next.Domain.Logs;

public sealed class TelegramOutboundLogEntry
{
    public string MessageId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public long ChatId { get; set; }
    public string? Text { get; set; }
    public string? ImageUrl { get; set; }
}
