namespace AchadinhosBot.Next.Domain.Logs;

public sealed class InstagramPublishLogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string Action { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string? DraftId { get; set; }
    public string? MediaId { get; set; }
    public string? Details { get; set; }
    public string? ProcessName { get; set; }
}
