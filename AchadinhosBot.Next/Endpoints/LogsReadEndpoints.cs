using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using Microsoft.AspNetCore.Mvc;

namespace AchadinhosBot.Next.Endpoints;

public static class LogsReadEndpoints
{
    public static void MapLogsReadEndpoints(this RouteGroupBuilder api)
    {
        api.MapGet("/logs/conversions", async (
            [FromQuery] string? store,
            [FromQuery] string? q,
            [FromQuery] int? limit,
            IConversionLogStore logStore,
            CancellationToken ct) =>
        {
            var query = new ConversionLogQuery
            {
                Store = store,
                Search = q,
                Limit = limit ?? 200
            };
            var items = await logStore.QueryAsync(query, ct);
            return Results.Ok(new { items });
        });

        api.MapGet("/logs/clicks", async (
            [FromQuery] string? q,
            [FromQuery] int? limit,
            IClickLogStore clickLogStore,
            CancellationToken ct) =>
        {
            var items = await clickLogStore.QueryAsync(null, q, limit ?? 200, ct);
            return Results.Ok(new { items });
        });

        api.MapGet("/logs/funnel", async (
            [FromQuery] int? hours,
            IConversionLogStore conversionLogStore,
            IClickLogStore clickLogStore,
            CancellationToken ct) =>
        {
            var windowHours = Math.Clamp(hours ?? 168, 1, 720);
            var since = DateTimeOffset.UtcNow.AddHours(-windowHours);
            var conversions = await conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 2000 }, ct);
            var clicks = await clickLogStore.QueryAsync(null, null, 2000, ct);

            var conversionsWindow = conversions
                .Where(x => x.Timestamp >= since)
                .ToList();
            var clicksWindow = clicks
                .Where(x => x.Timestamp >= since)
                .ToList();

            var bySource = clicksWindow
                .GroupBy(x => string.IsNullOrWhiteSpace(x.Source) ? "unknown" : x.Source.Trim().ToLowerInvariant())
                .Select(g => new
                {
                    source = g.Key,
                    clicks = g.Count(),
                    uniqueLinks = g
                        .Select(x => x.TargetUrl)
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Count()
                })
                .OrderByDescending(x => x.clicks)
                .Take(20)
                .ToArray();

            var byCampaign = clicksWindow
                .GroupBy(x => string.IsNullOrWhiteSpace(x.Campaign) ? "(none)" : x.Campaign!.Trim().ToLowerInvariant())
                .Select(g => new
                {
                    campaign = g.Key,
                    clicks = g.Count(),
                    uniqueLinks = g
                        .Select(x => x.TargetUrl)
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Count()
                })
                .OrderByDescending(x => x.clicks)
                .Take(20)
                .ToArray();

            var topLinks = clicksWindow
                .GroupBy(x => x.TargetUrl, StringComparer.OrdinalIgnoreCase)
                .Select(g => new
                {
                    targetUrl = g.Key,
                    clicks = g.Count(),
                    lastClickAt = g.Max(x => x.Timestamp),
                    source = g
                        .GroupBy(x => string.IsNullOrWhiteSpace(x.Source) ? "unknown" : x.Source.Trim().ToLowerInvariant())
                        .OrderByDescending(x => x.Count())
                        .Select(x => x.Key)
                        .FirstOrDefault() ?? "unknown",
                    campaign = g
                        .GroupBy(x => string.IsNullOrWhiteSpace(x.Campaign) ? "(none)" : x.Campaign!.Trim().ToLowerInvariant())
                        .OrderByDescending(x => x.Count())
                        .Select(x => x.Key)
                        .FirstOrDefault() ?? "(none)"
                })
                .OrderByDescending(x => x.clicks)
                .ThenByDescending(x => x.lastClickAt)
                .Take(30)
                .ToArray();

            return Results.Ok(new
            {
                windowHours,
                since,
                totals = new
                {
                    clicks = clicksWindow.Count,
                    conversions = conversionsWindow.Count,
                    successfulConversions = conversionsWindow.Count(x => x.Success),
                    affiliatedConversions = conversionsWindow.Count(x => x.IsAffiliated),
                    trackedConversionLinks = conversionsWindow
                        .SelectMany(x => x.TrackingIds ?? new List<string>())
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Count()
                },
                bySource,
                byCampaign,
                topLinks
            });
        });

        api.MapGet("/logs/instagram-ai", async (
            [FromQuery] string? q,
            [FromQuery] int? limit,
            IInstagramAiLogStore logStore,
            CancellationToken ct) =>
        {
            var items = await logStore.ListAsync(Math.Clamp(limit ?? 200, 1, 200), ct);
            if (!string.IsNullOrWhiteSpace(q))
            {
                var term = q.Trim();
                items = items.Where(i =>
                    i.Provider.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                    i.Model.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                    (i.Error?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    i.InputSnippet.Contains(term, StringComparison.OrdinalIgnoreCase)).ToList();
            }
            return Results.Ok(new { items });
        });

        api.MapGet("/logs/instagram-publish", async (
            [FromQuery] string? q,
            [FromQuery] string? processName,
            [FromQuery] int? limit,
            IInstagramPublishLogStore logStore,
            CancellationToken ct) =>
        {
            var items = await logStore.ListAsync(Math.Clamp(limit ?? 200, 1, 200), ct);
            if (!string.IsNullOrWhiteSpace(processName))
            {
                var process = processName.Trim();
                if (string.Equals(process, InstagramProcessNames.Legacy, StringComparison.OrdinalIgnoreCase))
                {
                    items = items.Where(i => string.IsNullOrWhiteSpace(i.ProcessName)).ToList();
                }
                else
                {
                    items = items.Where(i =>
                        string.Equals(i.ProcessName?.Trim(), process, StringComparison.OrdinalIgnoreCase)
                    ).ToList();
                }
            }
            if (!string.IsNullOrWhiteSpace(q))
            {
                var term = q.Trim();
                items = items.Where(i =>
                    i.Action.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                    (i.Error?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (i.Details?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (i.MediaId?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (i.DraftId?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (i.ProcessName?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
                ).ToList();
            }
            return Results.Ok(new { items });
        });

        api.MapGet("/logs/media", async (
            [FromQuery] int? limit,
            IMediaFailureLogStore logStore,
            CancellationToken ct) =>
        {
            var items = await logStore.ListAsync(limit ?? 50, ct);
            return Results.Ok(new { items });
        });

        api.MapGet("/logs/whatsapp-official-blocked", async (
            [FromQuery] int? limit,
            [FromQuery] string? reason,
            IOfficialWhatsAppBlockedOfferStore logStore,
            CancellationToken ct) =>
        {
            var items = await logStore.ListAsync(limit ?? 100, ct);
            if (!string.IsNullOrWhiteSpace(reason))
            {
                items = items
                    .Where(x => (x.Reason?.Contains(reason.Trim(), StringComparison.OrdinalIgnoreCase) ?? false))
                    .ToArray();
            }

            return Results.Ok(new
            {
                items,
                summary = new
                {
                    total = items.Count,
                    byReason = items
                        .GroupBy(x => string.IsNullOrWhiteSpace(x.Reason) ? "unknown" : x.Reason.Trim(), StringComparer.OrdinalIgnoreCase)
                        .Select(g => new { reason = g.Key, count = g.Count() })
                        .OrderByDescending(x => x.count)
                        .ToArray()
                }
            });
        });
    }
}
