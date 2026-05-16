namespace AchadinhosBot.Next.Domain.Logs;

public sealed class ClickLogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string TrackingId { get; set; } = string.Empty;
    public string? TrackingSlug { get; set; }
    public string? VisitorId { get; set; }
    public string? SessionId { get; set; }
    public string? EventType { get; set; }
    public string? PageType { get; set; }
    public string? PageUrl { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public string Source { get; set; } = "LinkTracking";
    public string? Category { get; set; }
    public string? Campaign { get; set; }
    public string? OriginChannel { get; set; }
    public string? OriginSurface { get; set; }
    public string? ClickChannel { get; set; }
    public string? ClickSurface { get; set; }
    public string? SourceComponent { get; set; }
    public string? OfferId { get; set; }
    public string? DraftId { get; set; }
    public string? MediaId { get; set; }
    public string? Referrer { get; set; }
    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }
    public string? IpHash { get; set; }
    public string? Location { get; set; }
    public string? DeviceType { get; set; }
    public string? Browser { get; set; }
    public string? OperatingSystem { get; set; }
    public string? Language { get; set; }
    public string? Timezone { get; set; }
    public int? ScreenWidth { get; set; }
    public int? ScreenHeight { get; set; }
    public int? ViewportWidth { get; set; }
    public int? ViewportHeight { get; set; }
    public int? ScrollDepth { get; set; }
    public int? TimeOnPageMs { get; set; }
    public string? UtmSource { get; set; }
    public string? UtmMedium { get; set; }
    public string? UtmCampaign { get; set; }
    public string? UtmContent { get; set; }
    public string? UtmTerm { get; set; }
}
