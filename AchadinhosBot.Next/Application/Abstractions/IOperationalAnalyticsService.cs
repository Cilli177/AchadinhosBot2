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
