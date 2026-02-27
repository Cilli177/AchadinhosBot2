namespace AchadinhosBot.Next.Domain.Content;

public sealed class ContentCalendarItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset ScheduledAt { get; set; } = DateTimeOffset.UtcNow;
    public string PostType { get; set; } = "feed";
    public string SourceInput { get; set; } = string.Empty;
    public string OfferContext { get; set; } = string.Empty;
    public string ReferenceUrl { get; set; } = string.Empty;
    public string ReferenceCaption { get; set; } = string.Empty;
    public string ReferenceMediaUrl { get; set; } = string.Empty;
    public string OfferUrl { get; set; } = string.Empty;
    public string Keyword { get; set; } = string.Empty;
    public string GeneratedCaption { get; set; } = string.Empty;
    public string Hashtags { get; set; } = string.Empty;
    public string MediaUrl { get; set; } = string.Empty;
    public bool AutoPublish { get; set; } = true;
    public string Status { get; set; } = "planned";
    public string? DraftId { get; set; }
    public string? PublishedMediaId { get; set; }
    public string? Error { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset? LastAttemptAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
