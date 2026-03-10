using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Application.Services;

public sealed class OperationalAnalyticsService : IOperationalAnalyticsService
{
    private readonly IConversionLogStore _conversionLogStore;
    private readonly IClickLogStore _clickLogStore;
    private readonly IInstagramAiLogStore _instagramAiLogStore;
    private readonly IInstagramPublishLogStore _instagramPublishLogStore;
    private readonly IInstagramPublishStore _instagramPublishStore;
    private readonly ICatalogOfferStore _catalogOfferStore;

    public OperationalAnalyticsService(
        IConversionLogStore conversionLogStore,
        IClickLogStore clickLogStore,
        IInstagramAiLogStore instagramAiLogStore,
        IInstagramPublishLogStore instagramPublishLogStore,
        IInstagramPublishStore instagramPublishStore,
        ICatalogOfferStore catalogOfferStore)
    {
        _conversionLogStore = conversionLogStore;
        _clickLogStore = clickLogStore;
        _instagramAiLogStore = instagramAiLogStore;
        _instagramPublishLogStore = instagramPublishLogStore;
        _instagramPublishStore = instagramPublishStore;
        _catalogOfferStore = catalogOfferStore;
    }

    public async Task<OperationalAnalyticsSummary> GetSummaryAsync(int hours, CancellationToken cancellationToken)
    {
        var windowHours = Math.Clamp(hours, 1, 24 * 30);
        var end = DateTimeOffset.UtcNow;
        var start = end.AddHours(-windowHours);

        var conversions = await _conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 2000 }, cancellationToken);
        var clicks = await _clickLogStore.QueryAsync(null, 2000, cancellationToken);
        var aiLogs = await _instagramAiLogStore.ListAsync(2000, cancellationToken);
        var publishLogs = await _instagramPublishLogStore.ListAsync(2000, cancellationToken);
        var drafts = await _instagramPublishStore.ListAsync(cancellationToken);
        var activeCatalogItems = await _catalogOfferStore.ListAsync(null, 500, cancellationToken);

        var conversionWindow = conversions.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var clickWindow = clicks.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var aiWindow = aiLogs.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var publishWindow = publishLogs.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var draftWindow = drafts.Where(x => x.CreatedAt >= start && x.CreatedAt <= end).ToList();

        var conversionSuccess = conversionWindow.Count(x => x.Success);
        var conversionAffiliated = conversionWindow.Count(x => x.IsAffiliated);
        var aiSuccess = aiWindow.Count(x => x.Success);

        return new OperationalAnalyticsSummary
        {
            WindowHours = windowHours,
            WindowStart = start,
            WindowEnd = end,
            Conversions = new ConversionAnalyticsSummary
            {
                Total = conversionWindow.Count,
                Success = conversionSuccess,
                Affiliated = conversionAffiliated,
                SuccessRate = CalculateRate(conversionSuccess, conversionWindow.Count),
                AvgElapsedMs = conversionWindow.Count == 0 ? 0 : Math.Round(conversionWindow.Average(x => x.ElapsedMs), 2),
                TopStores = BuildBreakdown(conversionWindow, x => x.Store, 5),
                TopSources = BuildBreakdown(conversionWindow, x => x.Source, 5)
            },
            Clicks = new ClickAnalyticsSummary
            {
                Total = clickWindow.Count,
                UniqueTrackingIds = clickWindow.Select(x => x.TrackingId).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                TopSources = BuildBreakdown(clickWindow, x => x.Source, 5),
                TopCampaigns = BuildBreakdown(clickWindow, x => x.Campaign, 5)
            },
            InstagramPublish = new InstagramPublishAnalyticsSummary
            {
                DraftsCreated = publishWindow.Count(x => string.Equals(x.Action, "autopilot_draft_created", StringComparison.OrdinalIgnoreCase) && x.Success),
                Published = publishWindow.Count(x => string.Equals(x.Action, "publish", StringComparison.OrdinalIgnoreCase) && x.Success),
                Queued = publishWindow.Count(x => string.Equals(x.Action, "publish_queued", StringComparison.OrdinalIgnoreCase) && x.Success),
                Failed = publishWindow.Count(x => !x.Success),
                AutoPilotSkipped = publishWindow.Count(x => string.Equals(x.Action, "autopilot_candidate_skipped", StringComparison.OrdinalIgnoreCase)),
                CatalogSyncs = publishWindow.Count(x => string.Equals(x.Action, "catalog_sync_after_publish", StringComparison.OrdinalIgnoreCase) && x.Success),
                ScheduledPending = draftWindow.Count(x => string.Equals(x.Status, "scheduled", StringComparison.OrdinalIgnoreCase))
            },
            InstagramAi = new InstagramAiAnalyticsSummary
            {
                Total = aiWindow.Count,
                Success = aiSuccess,
                SuccessRate = CalculateRate(aiSuccess, aiWindow.Count),
                AvgLatencyMs = aiWindow.Count == 0 ? 0 : Math.Round(aiWindow.Average(x => x.DurationMs), 2),
                AvgQualityScore = aiWindow.Count == 0 ? 0 : Math.Round(aiWindow.Average(x => x.QualityScore), 2),
                Providers = aiWindow
                    .GroupBy(x => string.IsNullOrWhiteSpace(x.Provider) ? "unknown" : x.Provider, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(g => g.Count())
                    .Select(g =>
                    {
                        var success = g.Count(x => x.Success);
                        return new AiProviderScorecardItem
                        {
                            Provider = g.Key,
                            Total = g.Count(),
                            Success = success,
                            SuccessRate = CalculateRate(success, g.Count()),
                            AvgLatencyMs = Math.Round(g.Average(x => x.DurationMs), 2),
                            AvgQualityScore = Math.Round(g.Average(x => x.QualityScore), 2)
                        };
                    })
                    .ToList()
            },
            Catalog = new CatalogAnalyticsSummary
            {
                ActiveItems = activeCatalogItems.Count,
                TotalPublishedDrafts = draftWindow.Count(x => string.Equals(x.Status, "published", StringComparison.OrdinalIgnoreCase)),
                SyncEligibleDrafts = draftWindow.Count(x => x.SendToCatalog)
            }
        };
    }

    private static double CalculateRate(int success, int total)
        => total <= 0 ? 0 : Math.Round(success * 100d / total, 2);

    private static List<OperationalBreakdownItem> BuildBreakdown<T>(IEnumerable<T> source, Func<T, string?> selector, int take)
    {
        return source
            .Select(selector)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .GroupBy(x => x!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key)
            .Take(Math.Clamp(take, 1, 20))
            .Select(g => new OperationalBreakdownItem
            {
                Key = g.Key,
                Count = g.Count()
            })
            .ToList();
    }
}
