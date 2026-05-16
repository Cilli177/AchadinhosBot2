namespace AchadinhosBot.Next.Domain.Logs;

public sealed class WhatsAppNicheRouteEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string? SourceGroupId { get; set; }
    public string Slug { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public int Confidence { get; set; }
    public string? ProductName { get; set; }
    public string? ProductUrl { get; set; }
    public string? ProductIdentity { get; set; }
    public string? StoreName { get; set; }
    public string? TrackingUrl { get; set; }
    public string? TrackingId { get; set; }
    public string? TargetGroupId { get; set; }
    public bool HadImage { get; set; }
    public string? ImageSource { get; set; }
    public string? ResolvedImageUrl { get; set; }
    public bool ReusedCanonicalTracking { get; set; }
}

public sealed class WhatsAppNicheReviewItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Status { get; set; } = "pending";
    public string Reason { get; set; } = string.Empty;
    public int Confidence { get; set; }
    public string? SuggestedSlug { get; set; }
    public string? ProductName { get; set; }
    public string? ProductUrl { get; set; }
    public string? StoreName { get; set; }
    public string? PriceText { get; set; }
    public string? ImageUrl { get; set; }
    public string? OriginalText { get; set; }
    public string? SourceGroupId { get; set; }
    public DateTimeOffset? DecidedAtUtc { get; set; }
    public string? DecidedSlug { get; set; }
    public List<string> DecidedSlugs { get; set; } = new();
    public string? DecisionNote { get; set; }
}
