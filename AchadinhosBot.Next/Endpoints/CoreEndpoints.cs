using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AchadinhosBot.Next.Endpoints;

public static class CoreEndpoints
{
    public static void MapConverterEndpoint(this WebApplication app)
    {
        static bool IsAllowedHost(Uri uri)
        {
            if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var host = uri.Host.ToLowerInvariant();
            string[] allowed =
            {
                // Amazon
                "amazon.com.br", "www.amazon.com.br", "amazon.com", "www.amazon.com", "amzn.to", "a.co",
                // Shopee
                "shopee.com", "www.shopee.com", "shopee.com.br", "www.shopee.com.br", "shope.ee",
                // Shein
                "shein.com", "www.shein.com", "shein.com.br", "www.shein.com.br",
                // Mercado Livre
                "mercadolivre.com.br", "www.mercadolivre.com.br", "mlb.cl", "mercadolivre.com",
                // URL Shorteners (will be expanded and re-validated internally)
                "tinyurl.com", "bit.ly", "cutt.ly", "shorturl.at", "ow.ly", "t.co", "rb.gy", "is.gd", "tiny.cc"
            };

            return allowed.Any(a => host.Equals(a, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + a, StringComparison.OrdinalIgnoreCase));
        }

        static async Task LogAttemptAsync(string logPath, object payload, CancellationToken ct)
        {
            try
            {
                var dir = Path.GetDirectoryName(logPath);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var json = JsonSerializer.Serialize(payload);
                await File.AppendAllTextAsync(logPath, json + Environment.NewLine, ct);
            }
            catch
            {
                // logging falhou — não bloquear fluxo do usuário
            }
        }

        app.MapPost("/converter", async (
            ConvertRequest payload,
            HttpContext context,
            IMessageProcessor processor,
            IOptions<WebhookOptions> options,
            CancellationToken ct) =>
        {
            if (!context.Request.Headers.TryGetValue("x-api-key", out var provided) ||
                !SecretComparer.EqualsConstantTime(options.Value.ApiKey, provided.ToString()))
            {
                return Results.Json(new { success = false, message = "forbidden" }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(payload.Text))
            {
                return Results.BadRequest(new { success = false, message = "Link vazio ou inválido." });
            }

            if (!Uri.TryCreate(payload.Text.Trim(), UriKind.Absolute, out var uri) || !IsAllowedHost(uri))
            {
                return Results.BadRequest(new { success = false, message = "Domínio não suportado para conversão." });
            }

            var result = await processor.ProcessAsync(payload.Text, payload.Source ?? "Webhook", ct);

            var response = new
            {
                success = result.Success,
                converted = result.ConvertedText,
                convertedLinks = result.ConvertedLinks,
                source = result.Source,
                message = result.Success
                    ? "Link convertido com sucesso."
                    : "Não foi possível converter esse link agora."
            };

            _ = LogAttemptAsync(
                Path.Combine(AppContext.BaseDirectory, "logs", "converter-public.log"),
                new
                {
                    ts = DateTimeOffset.UtcNow,
                    input = payload.Text,
                    source = payload.Source ?? "Webhook",
                    host = uri.Host.ToLowerInvariant(),
                    response.success,
                    response.message,
                    response.convertedLinks
                },
                ct);

            return Results.Ok(response);
        }).RequireRateLimiting("converter");

        app.MapGet("/api/analytics/hot-deals", async (
            IOperationalAnalyticsService analytics,
            CancellationToken ct) =>
        {
            var deals = await analytics.GetHotDealsAsync(24, 3, ct);
            return Results.Ok(new { success = true, deals });
        });

        app.MapGet("/api/analytics/summary", async (
            HttpContext context,
            IOperationalAnalyticsService analytics,
            IClickLogStore clickLogStore,
            ISettingsStore settingsStore,
            CancellationToken ct) =>
        {
            var hoursRaw = context.Request.Query["hours"].ToString();
            var hours = int.TryParse(hoursRaw, out var parsedHours) ? parsedHours : 24;
            hours = Math.Clamp(hours, 1, 24 * 30);

            var summary = await analytics.GetSummaryAsync(hours, ct);
            var categorizedSummaries = await analytics.GetCategorizedSummaryAsync(hours, ct);
            var settings = await settingsStore.GetAsync(ct);
            var clickWindow = await clickLogStore.QueryAsync(null, null, 5000, ct);
            var since = DateTimeOffset.UtcNow.AddHours(-hours);
            var recent = clickWindow
                .Where(x => x.Timestamp >= since)
                .OrderByDescending(x => x.Timestamp)
                .Take(25)
                .Select(x => new
                {
                    timestamp = x.Timestamp,
                    category = string.IsNullOrWhiteSpace(x.Category) ? "default" : x.Category,
                    eventType = x.EventType,
                    pageType = x.PageType,
                    source = x.Source,
                    targetUrl = x.TargetUrl,
                    visitorId = x.VisitorId,
                    sessionId = x.SessionId,
                    deviceType = x.DeviceType,
                    browser = x.Browser
                })
                .ToArray();

            var categorized = categorizedSummaries.ToDictionary(
                x => string.IsNullOrWhiteSpace(x.Category) ? "default" : x.Category!,
                x => x.Total,
                StringComparer.OrdinalIgnoreCase);

            var providerUsage = (summary.InstagramAi?.Providers ?? [])
                .ToDictionary(
                    x => string.IsNullOrWhiteSpace(x.Provider) ? "unknown" : x.Provider,
                    x => x.Total,
                    StringComparer.OrdinalIgnoreCase);

            object BuildBudgetItem(string provider, int monthlyCallLimit, decimal estimatedCostPerCallUsd)
            {
                providerUsage.TryGetValue(provider, out var usedCalls);
                var normalizedLimit = Math.Max(0, monthlyCallLimit);
                var estimatedCost = estimatedCostPerCallUsd <= 0
                    ? 0
                    : Math.Round((decimal)usedCalls * estimatedCostPerCallUsd, 4, MidpointRounding.AwayFromZero);
                return new
                {
                    provider,
                    monthlyCallLimit = normalizedLimit,
                    usedCalls,
                    remainingCalls = normalizedLimit > 0 ? Math.Max(0, normalizedLimit - usedCalls) : 0,
                    estimatedCostPerCallUsd,
                    estimatedCostUsd = estimatedCost
                };
            }

            var aiUsageBudget = new
            {
                providers = new object[]
                {
                    BuildBudgetItem("openai", settings.OpenAI?.MonthlyCallLimit ?? 0, settings.OpenAI?.EstimatedCostPerCallUsd ?? 0),
                    BuildBudgetItem("gemini", settings.Gemini?.MonthlyCallLimit ?? 0, settings.Gemini?.EstimatedCostPerCallUsd ?? 0),
                    BuildBudgetItem("deepseek", settings.DeepSeek?.MonthlyCallLimit ?? 0, settings.DeepSeek?.EstimatedCostPerCallUsd ?? 0),
                    BuildBudgetItem("nemotron", settings.Nemotron?.MonthlyCallLimit ?? 0, settings.Nemotron?.EstimatedCostPerCallUsd ?? 0),
                    BuildBudgetItem("qwen", settings.Qwen?.MonthlyCallLimit ?? 0, settings.Qwen?.EstimatedCostPerCallUsd ?? 0),
                    BuildBudgetItem("vila", settings.VilaNvidia?.MonthlyCallLimit ?? 0, settings.VilaNvidia?.EstimatedCostPerCallUsd ?? 0)
                }
            };

            return Results.Ok(new
            {
                success = true,
                summary,
                aiUsageBudget,
                categorized,
                categorizedDetails = categorizedSummaries,
                totalClicks = summary.Clicks.Total,
                uniqueVisitors = summary.Clicks.UniqueVisitors,
                uniqueSessions = summary.Clicks.UniqueSessions,
                topSources = summary.Clicks.TopSources,
                topCampaigns = summary.Clicks.TopCampaigns,
                topEventTypes = summary.Clicks.TopEventTypes,
                topPageTypes = summary.Clicks.TopPageTypes,
                topDevices = summary.Clicks.TopDevices,
                topBrowsers = summary.Clicks.TopBrowsers,
                recentItems = recent
            });
        });

        app.MapPost("/api/analytics/click", async (
            HttpContext context,
            IClickLogStore store,
            CancellationToken ct) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var body = await reader.ReadToEndAsync(ct);
            var payload = JsonSerializer.Deserialize<ClickTelemetryRequest>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (payload == null || string.IsNullOrWhiteSpace(payload.TargetUrl))
            {
                return Results.BadRequest();
            }

            var userAgent = context.Request.Headers.UserAgent.ToString();
            var (browser, operatingSystem, deviceType) = ParseUserAgent(userAgent);
            var ipAddress = context.Request.Headers["X-Forwarded-For"].FirstOrDefault() ?? context.Connection.RemoteIpAddress?.ToString();
            var normalizedSource = payload.Source ?? "Unknown";
            var normalizedPageType = NormalizeTelemetryToken(payload.PageType) ?? InferPageType(payload.Category, normalizedSource, payload.TargetUrl, payload.PageUrl);
            var normalizedEventType = NormalizeTelemetryToken(payload.EventType) ?? InferEventType(normalizedSource, payload.TargetUrl);

            var entry = new ClickLogEntry
            {
                TargetUrl = payload.TargetUrl,
                Source = normalizedSource,
                Category = string.IsNullOrWhiteSpace(payload.Category) ? null : payload.Category.Trim().ToLowerInvariant(),
                TrackingId = payload.TrackingId ?? string.Empty,
                Campaign = payload.Campaign,
                VisitorId = NormalizeTelemetryToken(payload.VisitorId),
                SessionId = NormalizeTelemetryToken(payload.SessionId),
                EventType = normalizedEventType,
                PageType = normalizedPageType,
                PageUrl = payload.PageUrl,
                SourceComponent = NormalizeTelemetryToken(payload.SourceComponent),
                OfferId = NormalizeTelemetryToken(payload.OfferId),
                DraftId = NormalizeTelemetryToken(payload.DraftId),
                MediaId = NormalizeTelemetryToken(payload.MediaId),
                Referrer = context.Request.Headers.Referer.ToString(),
                UserAgent = userAgent,
                IpAddress = ipAddress,
                IpHash = ComputeStableHash(ipAddress),
                Location = context.Request.Headers["CF-IPCountry"].FirstOrDefault() ?? "Unknown",
                DeviceType = deviceType,
                Browser = browser,
                OperatingSystem = operatingSystem,
                Language = NormalizeTelemetryToken(payload.Language) ?? NormalizeTelemetryToken(context.Request.Headers.AcceptLanguage.ToString().Split(',').FirstOrDefault()),
                Timezone = NormalizeTelemetryToken(payload.Timezone),
                ScreenWidth = payload.ScreenWidth,
                ScreenHeight = payload.ScreenHeight,
                ViewportWidth = payload.ViewportWidth,
                ViewportHeight = payload.ViewportHeight,
                ScrollDepth = payload.ScrollDepth,
                TimeOnPageMs = payload.TimeOnPageMs,
                UtmSource = NormalizeTelemetryToken(payload.UtmSource),
                UtmMedium = NormalizeTelemetryToken(payload.UtmMedium),
                UtmCampaign = NormalizeTelemetryToken(payload.UtmCampaign),
                UtmContent = NormalizeTelemetryToken(payload.UtmContent),
                UtmTerm = NormalizeTelemetryToken(payload.UtmTerm)
            };

            await store.AppendAsync(entry, payload.Category, ct);
            return Results.Ok(new { success = true });
        });
    }

    public sealed record ClickTelemetryRequest(
        string TargetUrl,
        string? Source,
        string? TrackingId,
        string? Campaign,
        string? Category,
        string? VisitorId = null,
        string? SessionId = null,
        string? EventType = null,
        string? PageType = null,
        string? PageUrl = null,
        string? SourceComponent = null,
        string? OfferId = null,
        string? DraftId = null,
        string? MediaId = null,
        string? Language = null,
        string? Timezone = null,
        int? ScreenWidth = null,
        int? ScreenHeight = null,
        int? ViewportWidth = null,
        int? ViewportHeight = null,
        int? ScrollDepth = null,
        int? TimeOnPageMs = null,
        string? UtmSource = null,
        string? UtmMedium = null,
        string? UtmCampaign = null,
        string? UtmContent = null,
        string? UtmTerm = null);

    private static string? InferEventType(string? source, string? targetUrl)
    {
        var normalizedSource = source?.Trim().ToLowerInvariant() ?? string.Empty;
        var normalizedTarget = targetUrl?.Trim().ToLowerInvariant() ?? string.Empty;

        if (normalizedSource.Contains("view")) return "page_view";
        if (normalizedSource.Contains("buy") || normalizedSource.Contains("open_offer") || normalizedSource.Contains("open_link")) return "checkout_intent";
        if (normalizedSource.Contains("copy")) return "copy_action";
        if (normalizedSource.Contains("share")) return "share_action";
        if (normalizedSource.Contains("convert")) return "convert_action";
        if (normalizedTarget.Contains("/item/")) return "offer_detail_click";
        if (normalizedTarget.Contains("/catalogo")) return "catalog_navigation";
        return "click";
    }

    private static string? InferPageType(string? category, string? source, string? targetUrl, string? pageUrl)
    {
        var normalizedCategory = category?.Trim().ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(normalizedCategory))
        {
            return normalizedCategory;
        }

        var combined = string.Join(" ", new[] { source, targetUrl, pageUrl }.Where(x => !string.IsNullOrWhiteSpace(x))).ToLowerInvariant();
        if (combined.Contains("/item/")) return "item";
        if (combined.Contains("/catalogo")) return "catalog";
        if (combined.Contains("/conversor-admin")) return "admin";
        if (combined.Contains("/conversor")) return "converter";
        if (combined.Contains("bio.reidasofertas") || combined.Contains("/bio")) return "bio";
        return null;
    }

    private static string? NormalizeTelemetryToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim();
        return normalized.Length > 160 ? normalized[..160] : normalized;
    }

    private static string? ComputeStableHash(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim()));
        return Convert.ToHexString(bytes);
    }

    private static (string Browser, string OperatingSystem, string DeviceType) ParseUserAgent(string? userAgent)
    {
        var ua = userAgent?.ToLowerInvariant() ?? string.Empty;

        var browser = "unknown";
        if (ua.Contains("edg/")) browser = "edge";
        else if (ua.Contains("chrome/")) browser = "chrome";
        else if (ua.Contains("safari/") && !ua.Contains("chrome/")) browser = "safari";
        else if (ua.Contains("firefox/")) browser = "firefox";

        var operatingSystem = "unknown";
        if (ua.Contains("windows")) operatingSystem = "windows";
        else if (ua.Contains("android")) operatingSystem = "android";
        else if (ua.Contains("iphone") || ua.Contains("ipad") || ua.Contains("ios")) operatingSystem = "ios";
        else if (ua.Contains("mac os")) operatingSystem = "macos";
        else if (ua.Contains("linux")) operatingSystem = "linux";

        var deviceType = (ua.Contains("mobile") || ua.Contains("android") || ua.Contains("iphone")) ? "mobile" : "desktop";
        if (ua.Contains("ipad") || ua.Contains("tablet"))
        {
            deviceType = "tablet";
        }

        return (browser, operatingSystem, deviceType);
    }

    public static void MapHealthEndpoints(this WebApplication app, bool startTelegramBotWorker, bool startTelegramUserbotWorker)
    {
        app.MapGet("/health", () => Results.Ok(new
        {
            status = "ok",
            service = "AchadinhosBot.Next",
            ts = DateTimeOffset.UtcNow,
            telegramBotWorkerEnabled = startTelegramBotWorker,
            telegramUserbotWorkerEnabled = startTelegramUserbotWorker
        }));

        app.MapGet("/health/live", () => Results.Ok(new
        {
            status = "ok",
            service = "AchadinhosBot.Next",
            kind = "liveness",
            ts = DateTimeOffset.UtcNow
        }));

        app.MapGet("/health/ready", (ITelegramUserbotService userbot) =>
        {
            var userbotReady = !startTelegramUserbotWorker || userbot.IsReady;
            var ready = userbotReady;

            if (!ready)
            {
                return Results.Json(new
                {
                    status = "degraded",
                    kind = "readiness",
                    telegramUserbotReady = userbotReady,
                    ts = DateTimeOffset.UtcNow
                }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            return Results.Ok(new
            {
                status = "ok",
                kind = "readiness",
                telegramUserbotReady = userbotReady,
                ts = DateTimeOffset.UtcNow
            });
        });
    }
}
