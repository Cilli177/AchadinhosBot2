namespace AchadinhosBot.Next.Domain.Logs;

public sealed class LinkTrackingEntry
{
    public string Id { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
    public string TargetUrl { get; set; } = string.Empty;
    public string Store { get; set; } = string.Empty;
    public string OriginChannel { get; set; } = "unknown";
    public string OriginSurface { get; set; } = "unknown";
    public string? Campaign { get; set; }
    public string? OfferId { get; set; }
    public string? DraftId { get; set; }
    public string? MessageId { get; set; }
    public int Clicks { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ExpiresAtUtc { get; set; }
    public DateTimeOffset? LastClickAt { get; set; }
}

public sealed class LinkTrackingCreateRequest
{
    public string TargetUrl { get; set; } = string.Empty;
    public string? Store { get; set; }
    public string? OriginChannel { get; set; }
    public string? OriginSurface { get; set; }
    public string? Campaign { get; set; }
    public string? OfferId { get; set; }
    public string? DraftId { get; set; }
    public string? MessageId { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }
}
