namespace AchadinhosBot.Next.Domain.Logs;

public sealed class ClickLogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string TrackingId { get; set; } = string.Empty;
    public string TargetUrl { get; set; } = string.Empty;
    public string Source { get; set; } = "LinkTracking";
    public string? Campaign { get; set; }
    public string? Referrer { get; set; }
    public string? UserAgent { get; set; }
    public string? IpHash { get; set; }
}
