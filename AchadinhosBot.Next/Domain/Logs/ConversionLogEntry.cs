namespace AchadinhosBot.Next.Domain.Logs;

public sealed class ConversionLogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = string.Empty;
    public string Store { get; set; } = "Unknown";
    public bool Success { get; set; }
    public int Clicks { get; set; }
    public bool IsAffiliated { get; set; }
    public string? ValidationError { get; set; }
    public bool AffiliateCorrected { get; set; }
    public string? AffiliateCorrectionNote { get; set; }
    public string? Error { get; set; }
    public List<string> TrackingIds { get; set; } = new();
    public string OriginalUrl { get; set; } = string.Empty;
    public string ConvertedUrl { get; set; } = string.Empty;
    public long? OriginChatId { get; set; }
    public long? DestinationChatId { get; set; }
    public string? OriginChatRef { get; set; }
    public string? DestinationChatRef { get; set; }
    public long ElapsedMs { get; set; }
}
