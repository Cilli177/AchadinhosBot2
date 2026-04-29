namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOperationalAnalyticsService
{
    Task<OperationalAnalyticsSummary> GetSummaryAsync(int hours, CancellationToken cancellationToken);
    Task<List<ClickAnalyticsSummary>> GetCategorizedSummaryAsync(int hours, CancellationToken cancellationToken);
    Task<IReadOnlyList<HotDealItem>> GetHotDealsAsync(int hours, int limit, CancellationToken cancellationToken);
}

public sealed class HotDealItem
{
    public string ProductId { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string ImageUrl { get; set; } = string.Empty;
    public string? Price { get; set; }
    public string? PreviousPrice { get; set; }
    public int? DiscountPercent { get; set; }
    public string AffiliateUrl { get; set; } = string.Empty;
    public int ViewCount { get; set; }
    public string Store { get; set; } = string.Empty;
}

public sealed class OperationalAnalyticsSummary
{
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public int WindowHours { get; set; }
    public DateTimeOffset WindowStart { get; set; }
    public DateTimeOffset WindowEnd { get; set; }
    public ConversionAnalyticsSummary Conversions { get; set; } = new();
    public ClickAnalyticsSummary Clicks { get; set; } = new();
    public InstagramPublishAnalyticsSummary InstagramPublish { get; set; } = new();
    public InstagramAiAnalyticsSummary InstagramAi { get; set; } = new();
    public CatalogAnalyticsSummary Catalog { get; set; } = new();
    public TrackingAnalyticsSummary Tracking { get; set; } = new();
}

public sealed class ConversionAnalyticsSummary
{
    public int Total { get; set; }
    public int Success { get; set; }
    public int Affiliated { get; set; }
    public double SuccessRate { get; set; }
    public double AvgElapsedMs { get; set; }
    public List<OperationalBreakdownItem> TopStores { get; set; } = new();
    public List<OperationalBreakdownItem> TopSources { get; set; } = new();
}

public sealed class ClickAnalyticsSummary
{
    public string? Category { get; set; }
    public int Total { get; set; }
    public int UniqueTrackingIds { get; set; }
    public int UniqueVisitors { get; set; }
    public int UniqueSessions { get; set; }
    public List<OperationalBreakdownItem> TopSources { get; set; } = new();
    public List<OperationalBreakdownItem> TopCampaigns { get; set; } = new();
    public List<OperationalBreakdownItem> TopEventTypes { get; set; } = new();
    public List<OperationalBreakdownItem> TopPageTypes { get; set; } = new();
    public List<OperationalBreakdownItem> TopDevices { get; set; } = new();
    public List<OperationalBreakdownItem> TopBrowsers { get; set; } = new();
}

public sealed class InstagramPublishAnalyticsSummary
{
    public int DraftsCreated { get; set; }
    public int Published { get; set; }
    public int Queued { get; set; }
    public int Failed { get; set; }
    public int AutoPilotSkipped { get; set; }
    public int CatalogSyncs { get; set; }
    public int ScheduledPending { get; set; }
}

public sealed class InstagramAiAnalyticsSummary
{
    public int Total { get; set; }
    public int Success { get; set; }
    public double SuccessRate { get; set; }
    public double AvgLatencyMs { get; set; }
    public double AvgQualityScore { get; set; }
    public List<AiProviderScorecardItem> Providers { get; set; } = new();
}

public sealed class CatalogAnalyticsSummary
{
    public int ActiveItems { get; set; }
    public int TotalPublishedDrafts { get; set; }
    public int SyncEligibleDrafts { get; set; }
}

public sealed class TrackingAnalyticsSummary
{
    public int TotalLinksCreated { get; set; }
    public int TotalLinksClicked { get; set; }
    public int LinksWithClicks { get; set; }
    public double AvgClicksPerLink { get; set; }
    public TrackingFunnelSummary Funnel { get; set; } = new();
    public List<OperationalBreakdownItem> TopOriginSurfaces { get; set; } = new();
    public List<OperationalBreakdownItem> TopClickSurfaces { get; set; } = new();
    public List<OperationalBreakdownItem> TopCampaigns { get; set; } = new();
    public List<OperationalBreakdownItem> TopStores { get; set; } = new();
    public List<TrackingSurfacePerformanceItem> SurfacePerformance { get; set; } = new();
    public List<TrackingStoreChannelItem> StoreChannelPerformance { get; set; } = new();
    public List<TrackingSurfaceMatrixItem> SurfaceMatrix { get; set; } = new();
    public List<TrackingLinkPerformanceItem> LowEngagementLinks { get; set; } = new();
    public List<TrackingLinkPerformanceItem> TopOffers { get; set; } = new();
    public List<TrackingInsightItem> StrategicInsights { get; set; } = new();
}

public sealed class TrackingFunnelSummary
{
    public int Generated { get; set; }
    public int PublishedOrEmitted { get; set; }
    public int Clicked { get; set; }
}

public sealed class TrackingSurfacePerformanceItem
{
    public string Surface { get; set; } = string.Empty;
    public int LinksCreated { get; set; }
    public int Clicks { get; set; }
    public int ClickedLinks { get; set; }
    public double Ctr { get; set; }
}

public sealed class TrackingStoreChannelItem
{
    public string Store { get; set; } = string.Empty;
    public string Channel { get; set; } = string.Empty;
    public int Clicks { get; set; }
}

public sealed class TrackingSurfaceMatrixItem
{
    public string OriginSurface { get; set; } = string.Empty;
    public string ClickSurface { get; set; } = string.Empty;
    public int Count { get; set; }
}

public sealed class TrackingLinkPerformanceItem
{
    public string TrackingId { get; set; } = string.Empty;
    public string? TrackingSlug { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public string Store { get; set; } = string.Empty;
    public string OriginSurface { get; set; } = string.Empty;
    public string? Campaign { get; set; }
    public int Clicks { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class TrackingInsightItem
{
    public string Title { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string Strength { get; set; } = "sinal_fraco";
}

public sealed class OperationalBreakdownItem
{
    public string Key { get; set; } = string.Empty;
    public int Count { get; set; }
}

public sealed class AiProviderScorecardItem
{
    public string Provider { get; set; } = string.Empty;
    public int Total { get; set; }
    public int Success { get; set; }
    public double SuccessRate { get; set; }
    public double AvgLatencyMs { get; set; }
    public double AvgQualityScore { get; set; }
}
