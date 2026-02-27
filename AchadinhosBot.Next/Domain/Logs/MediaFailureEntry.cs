namespace AchadinhosBot.Next.Domain.Logs;

public sealed class MediaFailureEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = "TelegramUserbot";
    public long? OriginChatId { get; set; }
    public string? DestinationChatRef { get; set; }
    public bool Success { get; set; }
    public string? Reason { get; set; }
    public string? Detail { get; set; }
}
