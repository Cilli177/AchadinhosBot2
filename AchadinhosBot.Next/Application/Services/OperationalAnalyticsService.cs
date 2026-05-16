using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using Microsoft.Extensions.Caching.Memory;

namespace AchadinhosBot.Next.Application.Services;

public sealed class OperationalAnalyticsService : IOperationalAnalyticsService
{
    private readonly IConversionLogStore _conversionLogStore;
    private readonly IClickLogStore _clickLogStore;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly IInstagramAiLogStore _instagramAiLogStore;
    private readonly IInstagramPublishLogStore _instagramPublishLogStore;
    private readonly IInstagramPublishStore _instagramPublishStore;
    private readonly ICatalogOfferStore _catalogOfferStore;
    private readonly IMemoryCache _cache;
    private static readonly TimeSpan SummaryCacheTtl = TimeSpan.FromSeconds(20);

    public OperationalAnalyticsService(
        IConversionLogStore conversionLogStore,
        IClickLogStore clickLogStore,
        ILinkTrackingStore linkTrackingStore,
        IInstagramAiLogStore instagramAiLogStore,
        IInstagramPublishLogStore instagramPublishLogStore,
        IInstagramPublishStore instagramPublishStore,
        ICatalogOfferStore catalogOfferStore)
        : this(
            conversionLogStore,
            clickLogStore,
            linkTrackingStore,
            instagramAiLogStore,
            instagramPublishLogStore,
            instagramPublishStore,
            catalogOfferStore,
            new MemoryCache(new MemoryCacheOptions()))
    {
    }

    public OperationalAnalyticsService(
        IConversionLogStore conversionLogStore,
        IClickLogStore clickLogStore,
        ILinkTrackingStore linkTrackingStore,
        IInstagramAiLogStore instagramAiLogStore,
        IInstagramPublishLogStore instagramPublishLogStore,
        IInstagramPublishStore instagramPublishStore,
        ICatalogOfferStore catalogOfferStore,
        IMemoryCache cache)
    {
        _conversionLogStore = conversionLogStore;
        _clickLogStore = clickLogStore;
        _linkTrackingStore = linkTrackingStore;
        _instagramAiLogStore = instagramAiLogStore;
        _instagramPublishLogStore = instagramPublishLogStore;
        _instagramPublishStore = instagramPublishStore;
        _catalogOfferStore = catalogOfferStore;
        _cache = cache;
    }

    public async Task<OperationalAnalyticsSummary> GetSummaryAsync(int hours, CancellationToken cancellationToken)
    {
        var windowHours = Math.Clamp(hours, 1, 24 * 30);
        var cacheKey = $"analytics:summary:{windowHours}";
        if (_cache.TryGetValue(cacheKey, out OperationalAnalyticsSummary? cachedSummary) && cachedSummary is not null)
        {
            return cachedSummary;
        }

        var end = DateTimeOffset.UtcNow;
        var start = end.AddHours(-windowHours);

        var conversionsTask = _conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 2000 }, cancellationToken);
        var clicksTask = _clickLogStore.QueryAsync(null, null, 2000, cancellationToken);
        var trackingEntriesTask = _linkTrackingStore.ListAsync(cancellationToken);
        var aiLogsTask = _instagramAiLogStore.ListAsync(2000, cancellationToken);
        var publishLogsTask = _instagramPublishLogStore.ListAsync(2000, cancellationToken);
        var draftsTask = _instagramPublishStore.ListAsync(cancellationToken);
        var activeCatalogItemsTask = _catalogOfferStore.ListAsync(null, 500, cancellationToken, CatalogTargets.Both);
        await Task.WhenAll(conversionsTask, clicksTask, trackingEntriesTask, aiLogsTask, publishLogsTask, draftsTask, activeCatalogItemsTask);

        var conversions = await conversionsTask;
        var clicks = await clicksTask;
        var trackingEntries = await trackingEntriesTask;
        var aiLogs = await aiLogsTask;
        var publishLogs = await publishLogsTask;
        var drafts = await draftsTask;
        var activeCatalogItems = await activeCatalogItemsTask;

        var conversionWindow = conversions.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var clickWindow = clicks.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var trackingWindow = trackingEntries.Where(x => x.CreatedAt >= start && x.CreatedAt <= end).ToList();
        var aiWindow = aiLogs.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var publishWindow = publishLogs.Where(x => x.Timestamp >= start && x.Timestamp <= end).ToList();
        var draftWindow = drafts.Where(x => x.CreatedAt >= start && x.CreatedAt <= end).ToList();

        var conversionSuccess = conversionWindow.Count(x => x.Success);
        var conversionAffiliated = conversionWindow.Count(x => x.IsAffiliated);
        var aiSuccess = aiWindow.Count(x => x.Success);

        var summary = new OperationalAnalyticsSummary
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
                UniqueVisitors = clickWindow.Select(x => x.VisitorId).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                UniqueSessions = clickWindow.Select(x => x.SessionId).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                TopSources = BuildBreakdown(clickWindow, x => x.Source, 5),
                TopCampaigns = BuildBreakdown(clickWindow, x => x.Campaign, 5),
                TopEventTypes = BuildBreakdown(clickWindow, x => x.EventType, 5),
                TopPageTypes = BuildBreakdown(clickWindow, x => x.PageType, 5),
                TopDevices = BuildBreakdown(clickWindow, x => x.DeviceType, 5),
                TopBrowsers = BuildBreakdown(clickWindow, x => x.Browser, 5)
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
                SyncEligibleDrafts = draftWindow.Count(x => CatalogTargets.IsEnabled(x.CatalogTarget, x.SendToCatalog))
            },
            Tracking = BuildTrackingSummary(trackingEntries, trackingWindow, clickWindow)
        };

        _cache.Set(cacheKey, summary, SummaryCacheTtl);
        return summary;
    }

    public async Task<IReadOnlyList<HotDealItem>> GetHotDealsAsync(int hours, int limit, CancellationToken cancellationToken)
    {
        var windowHours = Math.Clamp(hours, 1, 168); // Max 1 week
        var normalizedLimit = Math.Clamp(limit, 1, 24);
        var cacheKey = $"analytics:hot-deals:{windowHours}:{normalizedLimit}";
        if (_cache.TryGetValue(cacheKey, out List<HotDealItem>? cachedDeals) && cachedDeals is not null)
        {
            return cachedDeals;
        }

        var start = DateTimeOffset.UtcNow.AddHours(-windowHours);

        var clicks = await _clickLogStore.QueryAsync(null, null, 5000, cancellationToken);
        var clickWindow = clicks.Where(x => x.Timestamp >= start).ToList();

        // Group by TargetUrl to find most viewed items
        var topUrls = clickWindow
            .Where(x => !string.IsNullOrWhiteSpace(x.TargetUrl))
            .GroupBy(x => x.TargetUrl, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Take(normalizedLimit * 3)
            .Select(g => new { Url = g.Key, Count = g.Count() })
            .ToList();

        var catalogItems = await _catalogOfferStore.ListAsync(null, 500, cancellationToken, CatalogTargets.Both);
        var activeItems = catalogItems.Where(x => x.Active).ToList();

        var deals = new List<HotDealItem>();
        foreach (var top in topUrls)
        {
            var match = activeItems.FirstOrDefault(x => 
                string.Equals(x.OfferUrl, top.Url, StringComparison.OrdinalIgnoreCase) ||
                (top.Url.Contains(x.Id, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(x.Id)));

            if (match != null && deals.All(d => d.ProductId != match.Id))
            {
                deals.Add(new HotDealItem
                {
                    ProductId = match.Id,
                    ProductName = match.ProductName,
                    ImageUrl = match.ImageUrl ?? string.Empty,
                    Price = match.PriceText,
                    AffiliateUrl = match.OfferUrl,
                    ViewCount = top.Count,
                    Store = match.Store
                });

                if (deals.Count >= normalizedLimit) break;
            }
        }

        if (deals.Count < normalizedLimit)
        {
            var newest = activeItems
                .Where(x => deals.All(d => d.ProductId != x.Id))
                .OrderByDescending(x => x.PublishedAt)
                .Take(normalizedLimit - deals.Count);

            foreach (var item in newest)
            {
                deals.Add(new HotDealItem
                {
                    ProductId = item.Id,
                    ProductName = item.ProductName,
                    ImageUrl = item.ImageUrl ?? string.Empty,
                    Price = item.PriceText,
                    AffiliateUrl = item.OfferUrl,
                    ViewCount = 0,
                    Store = item.Store
                });
            }
        }

        _cache.Set(cacheKey, deals, SummaryCacheTtl);
        return deals;
    }

    public async Task<List<ClickAnalyticsSummary>> GetCategorizedSummaryAsync(int hours, CancellationToken cancellationToken)
    {
        var windowHours = Math.Clamp(hours, 1, 168);
        var cacheKey = $"analytics:categorized:{windowHours}";
        if (_cache.TryGetValue(cacheKey, out List<ClickAnalyticsSummary>? cachedCategories) && cachedCategories is not null)
        {
            return cachedCategories;
        }

        var start = DateTimeOffset.UtcNow.AddHours(-windowHours);
        var categories = new[] { "bio", "catalog", "converter", null };
        var result = new List<ClickAnalyticsSummary>();

        foreach (var cat in categories)
        {
            var clicks = await _clickLogStore.QueryAsync(cat, null, 2000, cancellationToken);
            var window = clicks.Where(x => x.Timestamp >= start).ToList();
            
            result.Add(new ClickAnalyticsSummary
            {
                Category = cat ?? "default",
                Total = window.Count,
                UniqueTrackingIds = window.Select(x => x.TrackingId).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                UniqueVisitors = window.Select(x => x.VisitorId).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                UniqueSessions = window.Select(x => x.SessionId).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                TopSources = BuildBreakdown(window, x => x.Source, 5),
                TopCampaigns = BuildBreakdown(window, x => x.Campaign, 5),
                TopEventTypes = BuildBreakdown(window, x => x.EventType, 5),
                TopPageTypes = BuildBreakdown(window, x => x.PageType, 5),
                TopDevices = BuildBreakdown(window, x => x.DeviceType, 5),
                TopBrowsers = BuildBreakdown(window, x => x.Browser, 5)
            });
        }

        _cache.Set(cacheKey, result, SummaryCacheTtl);
        return result;
    }

    private static double CalculateRate(int success, int total)
        => total <= 0 ? 0 : Math.Round(success * 100d / total, 2);

    private static TrackingAnalyticsSummary BuildTrackingSummary(
        IReadOnlyList<LinkTrackingEntry> allTrackingEntries,
        List<LinkTrackingEntry> trackingWindow,
        List<ClickLogEntry> clickWindow)
    {
        var allEntriesByKey = allTrackingEntries
            .SelectMany(entry => ResolveTrackingKeys(entry).Select(key => new { Key = key, Entry = entry }))
            .GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Entry, StringComparer.OrdinalIgnoreCase);

        var clickGroups = clickWindow
            .Select(click =>
            {
                var key = ResolveTrackingKey(click);
                allEntriesByKey.TryGetValue(key, out var entry);
                var originSurface = TrackingAttributionHelper.NormalizeSurface(click.OriginSurface, entry?.OriginSurface ?? "unknown");
                var clickSurface = TrackingAttributionHelper.InferClickAttribution(
                    click.ClickSurface ?? click.Source,
                    click.PageType,
                    click.PageUrl,
                    click.Referrer,
                    click.TargetUrl,
                    click.OriginSurface ?? entry?.OriginSurface).ClickSurface;

                return new
                {
                    Key = key,
                    Entry = entry,
                    Click = click,
                    OriginSurface = originSurface,
                    ClickSurface = clickSurface,
                    ClickChannel = TrackingAttributionHelper.ResolveChannelFromSurface(clickSurface),
                    Store = entry?.Store ?? "unknown",
                    Campaign = click.Campaign ?? entry?.Campaign
                };
            })
            .ToList();

        var clickCountsByKey = clickGroups
            .Where(x => !string.IsNullOrWhiteSpace(x.Key))
            .GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var linksWithClicks = trackingWindow
            .Count(entry => ResolveTrackingKeys(entry).Any(key => clickCountsByKey.ContainsKey(key)));

        var publishedOrEmitted = trackingWindow.Count(x =>
        {
            var surface = TrackingAttributionHelper.NormalizeSurface(x.OriginSurface);
            return surface is not "conversor_web" and not "conversor_admin";
        });

        var topOffers = allTrackingEntries
            .Select(entry => new TrackingLinkPerformanceItem
            {
                TrackingId = entry.Id,
                TrackingSlug = string.IsNullOrWhiteSpace(entry.Slug) ? null : entry.Slug,
                TargetUrl = entry.TargetUrl,
                Store = string.IsNullOrWhiteSpace(entry.Store) ? "unknown" : entry.Store,
                OriginSurface = TrackingAttributionHelper.NormalizeSurface(entry.OriginSurface),
                Campaign = entry.Campaign,
                Clicks = ResolveTrackingKeys(entry)
                    .Where(key => clickCountsByKey.TryGetValue(key, out _))
                    .Select(key => clickCountsByKey[key])
                    .DefaultIfEmpty(entry.Clicks)
                    .Max(),
                CreatedAt = entry.CreatedAt
            })
            .Where(x => x.Clicks > 0)
            .OrderByDescending(x => x.Clicks)
            .ThenByDescending(x => x.CreatedAt)
            .Take(5)
            .ToList();

        var lowEngagementLinks = trackingWindow
            .Select(entry => new TrackingLinkPerformanceItem
            {
                TrackingId = entry.Id,
                TrackingSlug = string.IsNullOrWhiteSpace(entry.Slug) ? null : entry.Slug,
                TargetUrl = entry.TargetUrl,
                Store = string.IsNullOrWhiteSpace(entry.Store) ? "unknown" : entry.Store,
                OriginSurface = TrackingAttributionHelper.NormalizeSurface(entry.OriginSurface),
                Campaign = entry.Campaign,
                Clicks = ResolveTrackingKeys(entry)
                    .Where(key => clickCountsByKey.TryGetValue(key, out _))
                    .Select(key => clickCountsByKey[key])
                    .DefaultIfEmpty(0)
                    .Max(),
                CreatedAt = entry.CreatedAt
            })
            .Where(x => x.Clicks <= 1)
            .OrderBy(x => x.Clicks)
            .ThenByDescending(x => x.CreatedAt)
            .Take(5)
            .ToList();

        var surfacePerformance = trackingWindow
            .GroupBy(x => TrackingAttributionHelper.NormalizeSurface(x.OriginSurface), StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var matchingClicks = clickGroups.Where(x => string.Equals(x.OriginSurface, g.Key, StringComparison.OrdinalIgnoreCase)).ToList();
                var clickedLinks = g.Count(entry => ResolveTrackingKeys(entry).Any(key => clickCountsByKey.ContainsKey(key)));
                return new TrackingSurfacePerformanceItem
                {
                    Surface = g.Key,
                    LinksCreated = g.Count(),
                    Clicks = matchingClicks.Count,
                    ClickedLinks = clickedLinks,
                    Ctr = g.Count() == 0 ? 0 : Math.Round(clickedLinks * 100d / g.Count(), 2)
                };
            })
            .OrderByDescending(x => x.Ctr)
            .ThenByDescending(x => x.Clicks)
            .Take(8)
            .ToList();

        var storeChannelPerformance = clickGroups
            .Where(x => !string.IsNullOrWhiteSpace(x.Store))
            .GroupBy(x => new
            {
                Store = string.IsNullOrWhiteSpace(x.Store) ? "unknown" : x.Store,
                Channel = x.ClickChannel
            })
            .OrderByDescending(g => g.Count())
            .Take(8)
            .Select(g => new TrackingStoreChannelItem
            {
                Store = g.Key.Store,
                Channel = g.Key.Channel,
                Clicks = g.Count()
            })
            .ToList();

        var matrix = clickGroups
            .GroupBy(x => new { x.OriginSurface, x.ClickSurface })
            .OrderByDescending(g => g.Count())
            .Take(16)
            .Select(g => new TrackingSurfaceMatrixItem
            {
                OriginSurface = g.Key.OriginSurface,
                ClickSurface = g.Key.ClickSurface,
                Count = g.Count()
            })
            .ToList();

        return new TrackingAnalyticsSummary
        {
            TotalLinksCreated = trackingWindow.Count,
            TotalLinksClicked = clickWindow.Count,
            LinksWithClicks = linksWithClicks,
            AvgClicksPerLink = trackingWindow.Count == 0 ? 0 : Math.Round(clickWindow.Count / (double)trackingWindow.Count, 2),
            Funnel = new TrackingFunnelSummary
            {
                Generated = trackingWindow.Count,
                PublishedOrEmitted = publishedOrEmitted,
                Clicked = linksWithClicks
            },
            TopOriginSurfaces = BuildBreakdown(trackingWindow, x => TrackingAttributionHelper.NormalizeSurface(x.OriginSurface), 6),
            TopClickSurfaces = BuildBreakdown(clickGroups, x => x.ClickSurface, 6),
            TopCampaigns = BuildBreakdown(clickGroups, x => x.Campaign, 6),
            TopStores = BuildBreakdown(clickGroups, x => x.Store, 6),
            SurfacePerformance = surfacePerformance,
            StoreChannelPerformance = storeChannelPerformance,
            SurfaceMatrix = matrix,
            LowEngagementLinks = lowEngagementLinks,
            TopOffers = topOffers,
            StrategicInsights = BuildStrategicInsights(surfacePerformance, lowEngagementLinks, storeChannelPerformance)
        };
    }

    private static List<TrackingInsightItem> BuildStrategicInsights(
        List<TrackingSurfacePerformanceItem> surfacePerformance,
        List<TrackingLinkPerformanceItem> lowEngagementLinks,
        List<TrackingStoreChannelItem> storeChannelPerformance)
    {
        var insights = new List<TrackingInsightItem>();

        var bestSurface = surfacePerformance.FirstOrDefault();
        if (bestSurface is not null)
        {
            insights.Add(new TrackingInsightItem
            {
                Title = "Superfície com melhor tração",
                Message = bestSurface.LinksCreated < 5
                    ? $"{bestSurface.Surface} lidera por enquanto, mas ainda é sinal fraco com {bestSurface.LinksCreated} links."
                    : $"{bestSurface.Surface} está puxando a melhor taxa de clique do período, com {bestSurface.Ctr}% de links acionados.",
                Strength = bestSurface.LinksCreated < 5 ? "sinal_fraco" : "forte"
            });
        }

        var weakLinks = lowEngagementLinks.Where(x => x.Clicks == 0).Take(2).ToList();
        if (weakLinks.Count > 0)
        {
            insights.Add(new TrackingInsightItem
            {
                Title = "Links pedindo redistribuição",
                Message = weakLinks.Count < 2
                    ? $"{weakLinks[0].OriginSurface} gerou links sem clique relevante. Vale testar outra superfície ou CTA."
                    : $"{string.Join(" e ", weakLinks.Select(x => x.OriginSurface).Distinct(StringComparer.OrdinalIgnoreCase).Take(2))} têm links recentes sem clique. Bom ponto para revisar CTA e distribuição.",
                Strength = "sinal_medio"
            });
        }

        var bestStoreChannel = storeChannelPerformance.FirstOrDefault();
        if (bestStoreChannel is not null)
        {
            insights.Add(new TrackingInsightItem
            {
                Title = "Canal mais forte por loja",
                Message = bestStoreChannel.Clicks < 5
                    ? $"{bestStoreChannel.Channel} aparece melhor para {bestStoreChannel.Store}, mas ainda com amostra pequena."
                    : $"{bestStoreChannel.Channel} está performando melhor para {bestStoreChannel.Store} nesta janela.",
                Strength = bestStoreChannel.Clicks < 5 ? "sinal_fraco" : "forte"
            });
        }

        return insights;
    }

    private static IEnumerable<string> ResolveTrackingKeys(LinkTrackingEntry entry)
    {
        if (!string.IsNullOrWhiteSpace(entry.Id))
        {
            yield return entry.Id;
        }

        if (!string.IsNullOrWhiteSpace(entry.Slug))
        {
            yield return entry.Slug;
        }
    }

    private static string ResolveTrackingKey(ClickLogEntry click)
    {
        if (!string.IsNullOrWhiteSpace(click.TrackingId))
        {
            return click.TrackingId;
        }

        if (!string.IsNullOrWhiteSpace(click.TrackingSlug))
        {
            return click.TrackingSlug;
        }

        return string.Empty;
    }

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
