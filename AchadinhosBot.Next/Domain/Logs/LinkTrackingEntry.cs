namespace AchadinhosBot.Next.Domain.Logs;

public sealed class LinkTrackingEntry
{
    public string Id { get; set; } = string.Empty;
    public string TargetUrl { get; set; } = string.Empty;
    public int Clicks { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastClickAt { get; set; }
}
