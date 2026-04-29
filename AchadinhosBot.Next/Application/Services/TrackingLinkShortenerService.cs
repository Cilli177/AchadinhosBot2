using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class TrackingLinkShortenerService
{
    private readonly ILinkTrackingStore _trackingStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISettingsStore _settingsStore;
    private readonly IOptions<WebhookOptions> _webhookOptions;
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<TrackingLinkShortenerService> _logger;

    public TrackingLinkShortenerService(
        ILinkTrackingStore trackingStore,
        IHttpClientFactory httpClientFactory,
        ISettingsStore settingsStore,
        IOptions<WebhookOptions> webhookOptions,
        IMemoryCache memoryCache,
        ILogger<TrackingLinkShortenerService> logger)
    {
        _trackingStore = trackingStore;
        _httpClientFactory = httpClientFactory;
        _settingsStore = settingsStore;
        _webhookOptions = webhookOptions;
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public async Task<string> ApplyTrackingAsync(string? text, string originSurface, CancellationToken cancellationToken, string? store = null)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text ?? string.Empty;
        }

        var publicBaseUrl = await ResolvePublicBaseUrlAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            return text;
        }

        var matches = UrlRegex().Matches(text);
        if (matches.Count == 0)
        {
            return text;
        }

        var rebuilt = new System.Text.StringBuilder();
        var cursor = 0;
        foreach (Match match in matches)
        {
            if (!match.Success)
            {
                continue;
            }

            rebuilt.Append(text, cursor, match.Index - cursor);
            var rawUrl = match.Value.TrimEnd('.', ',', '!', '?', ')', ']', '}');
            var trailing = match.Value.Substring(rawUrl.Length);
            var tracked = await TrackSingleUrlAsync(rawUrl, originSurface, cancellationToken, store);
            rebuilt.Append(tracked);
            rebuilt.Append(trailing);
            cursor = match.Index + match.Length;
        }

        rebuilt.Append(text, cursor, text.Length - cursor);
        return rebuilt.ToString();
    }

    public async Task<string> TrackSingleUrlAsync(string? url, string originSurface, CancellationToken cancellationToken, string? store = null)
    {
        var normalizedUrl = (url ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(normalizedUrl))
        {
            return normalizedUrl;
        }

        if (TryNormalizeOfficialTrackedUrl(normalizedUrl, out var normalizedTrackedUrl))
        {
            return normalizedTrackedUrl;
        }

        if (IsWhatsAppInviteUrl(normalizedUrl))
        {
            return "https://chat.whatsapp.com/FhkbgV9fnUjKnOM4KGDCPX";
        }

        if (!Uri.TryCreate(normalizedUrl, UriKind.Absolute, out var normalizedUri))
        {
            return normalizedUrl;
        }

        if (IsOfficialReiDasOfertasUrl(normalizedUri))
        {
            return normalizedUrl;
        }

        var settings = await _settingsStore.GetAsync(cancellationToken);
        var publicBaseUrl = await ResolvePublicBaseUrlAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            return normalizedUrl;
        }

        var resolvedTargetUrl = await ResolveTrackingTargetAsync(normalizedUrl, cancellationToken);
        var effectiveStore = !string.IsNullOrWhiteSpace(store) && !string.Equals(store, "Unknown", StringComparison.OrdinalIgnoreCase)
            ? store
            : resolvedTargetUrl.Store;
        var expiresAtUtc = DateTimeOffset.UtcNow.AddDays(ResolveTrackingValidityDays(settings));
        var entry = await _trackingStore.CreateAsync(new LinkTrackingCreateRequest
        {
            TargetUrl = resolvedTargetUrl.TargetUrl,
            Store = effectiveStore,
            OriginSurface = originSurface,
            ExpiresAtUtc = expiresAtUtc
        }, cancellationToken);
        // Regra especial: Shopee usa o link direto da API (já convertido)
        if (ShouldUseExternalShortener(settings, originSurface, effectiveStore, resolvedTargetUrl.TargetUrl))
        {
            var externalUrl = await ShortenExternallyAsync(resolvedTargetUrl.TargetUrl, settings.LinkAutomation.ExternalShortenerProvider, cancellationToken);
            if (!string.IsNullOrWhiteSpace(externalUrl))
            {
                return externalUrl;
            }
        }

        var trackingId = string.IsNullOrWhiteSpace(entry.Slug) ? entry.Id : entry.Slug;
        var trackedUrl = BuildTrackedRedirectUrl(publicBaseUrl, trackingId, originSurface);
        if (!await IsTrackedUrlResolvableAsync(trackedUrl, cancellationToken))
        {
            _logger.LogWarning(
                "Tracking URL {TrackingUrl} nao resolveu publicamente. Usando a URL original {TargetUrl}.",
                trackedUrl,
                resolvedTargetUrl.TargetUrl);
            return resolvedTargetUrl.TargetUrl;
        }

        return trackedUrl;
    }

    private async Task<string?> ShortenExternallyAsync(string url, string provider, CancellationToken cancellationToken)
    {
        if (string.Equals(provider, "tinyurl", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var client = _httpClientFactory.CreateClient("default");
                var tinyUrlApi = $"http://tinyurl.com/api-create.php?url={Uri.EscapeDataString(url)}";
                
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(10));

                var response = await client.GetStringAsync(tinyUrlApi, cts.Token);
                if (!string.IsNullOrWhiteSpace(response) && response.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    return response.Trim();
                }
            }
            catch
            {
                // Fallback silencioso para o encurtador interno
            }
        }

        return null;
    }

    private static bool ShouldUseExternalShortener(AutomationSettings settings, string originSurface, string? effectiveStore, string targetUrl)
    {
        if (!settings.LinkAutomation.EnableExternalShortener)
        {
            return false;
        }

        var normalizedSurface = TrackingAttributionHelper.NormalizeSurface(originSurface);
        if (normalizedSurface.StartsWith("whatsapp_", StringComparison.Ordinal))
        {
            return false;
        }

        if (TryNormalizeOfficialTrackedUrl(targetUrl, out _))
        {
            return false;
        }

        return string.Equals(effectiveStore, "Amazon", StringComparison.OrdinalIgnoreCase)
            || string.Equals(effectiveStore, "Mercado Livre", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<string> ResolvePublicBaseUrlAsync(CancellationToken cancellationToken)
    {
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var candidate = settings.BioHub?.PublicBaseUrl;
        if (string.IsNullOrWhiteSpace(candidate))
        {
            candidate = _webhookOptions.Value.PublicBaseUrl;
        }

        return NormalizeTrackingRedirectBaseUrl(candidate);
    }

    private async Task<(string TargetUrl, string? Store)> ResolveTrackingTargetAsync(string targetUrl, CancellationToken cancellationToken)
    {
        var cacheKey = $"tracking-target:{targetUrl.Trim()}";
        if (_memoryCache.TryGetValue<(string TargetUrl, string? Store)>(cacheKey, out var cachedResult))
        {
            return cachedResult;
        }

        var resolvedUrl = targetUrl;
        if (ShouldExpandExternalShortener(targetUrl))
        {
            const int maxRetries = 2;
            for (var attempt = 0; attempt < maxRetries; attempt++)
            {
                try
                {
                    var client = _httpClientFactory.CreateClient("default");
                    using var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    cts.CancelAfter(TimeSpan.FromSeconds(attempt == 0 ? 8 : 5));
                    using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                    var finalUri = response.RequestMessage?.RequestUri?.ToString();
                    if (!string.IsNullOrWhiteSpace(finalUri))
                    {
                        resolvedUrl = finalUri.Trim();
                    }

                    break;
                }
                catch when (attempt < maxRetries - 1)
                {
                    // retry once
                }
                catch
                {
                    resolvedUrl = targetUrl;
                }
            }
        }

        var result = (resolvedUrl, ResolveStoreNameFromUrl(resolvedUrl));
        _memoryCache.Set(cacheKey, result, TimeSpan.FromMinutes(20));
        return result;
    }

    /// <summary>
    /// Resolves a store name hint from a URL without HTTP expansion. Usable from any scope.
    /// </summary>
    public static string? ResolveStoreHint(string? url) =>
        string.IsNullOrWhiteSpace(url) ? null : ResolveStoreNameFromUrl(url) is "Unknown" ? null : ResolveStoreNameFromUrl(url);

    private static string ResolveStoreNameFromUrl(string? url)
    {
        var value = (url ?? string.Empty).ToLowerInvariant();
        if (value.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase) || value.Contains("mercado-livre", StringComparison.OrdinalIgnoreCase) || value.Contains("meli.", StringComparison.OrdinalIgnoreCase))
            return "Mercado Livre";
        if (value.Contains("amazon.", StringComparison.OrdinalIgnoreCase) || value.Contains("amzn.to", StringComparison.OrdinalIgnoreCase))
            return "Amazon";
        if (value.Contains("shopee.", StringComparison.OrdinalIgnoreCase))
            return "Shopee";
        if (value.Contains("shein.", StringComparison.OrdinalIgnoreCase))
            return "Shein";
        if (value.Contains("magazineluiza", StringComparison.OrdinalIgnoreCase) || value.Contains("magalu", StringComparison.OrdinalIgnoreCase))
            return "Magazine Luiza";
        if (value.Contains("casasbahia", StringComparison.OrdinalIgnoreCase) || value.Contains("casas-bahia", StringComparison.OrdinalIgnoreCase))
            return "Casas Bahia";
        if (value.Contains("americanas", StringComparison.OrdinalIgnoreCase))
            return "Americanas";
        if (value.Contains("aliexpress", StringComparison.OrdinalIgnoreCase))
            return "AliExpress";
        if (value.Contains("kabum", StringComparison.OrdinalIgnoreCase))
            return "KaBuM";
        return "Unknown";
    }

    private static bool ShouldExpandExternalShortener(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.Trim().Trim('.').ToLowerInvariant();
        return host is "tinyurl.com"
            or "bit.ly"
            or "amzn.to"
            or "t.co"
            or "cutt.ly"
            or "short.gy"
            or "tiny.one"
            or "goo.gl"
            or "tiny.cc"
            or "is.gd"
            or "buff.ly"
            or "ow.ly"
            or "linktr.ee"
            or "compre.link"
            or "meli.la"
            or "meli.co"
            or "s.click.aliexpress.com"
            or "click.linksynergy.com"
            or "redirect.viglink.com";
    }

    private static bool IsWhatsAppInviteUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return string.Equals(uri.Host, "chat.whatsapp.com", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsOfficialReiDasOfertasUrl(Uri uri)
        => uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase) ||
           uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase);

    private static bool TryNormalizeOfficialTrackedUrl(string url, out string normalizedUrl)
    {
        normalizedUrl = string.Empty;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.AbsolutePath.StartsWith("/r/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase) &&
            !uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        normalizedUrl = $"https://reidasofertas.ia.br{uri.AbsolutePath}";
        return true;
    }

    private static string BuildTrackedRedirectUrl(string publicBaseUrl, string trackingId, string source)
    {
        var compactSource = ToTrackingSourceAlias(source);
        var parameters = new List<string>();
        if (!string.IsNullOrWhiteSpace(compactSource) && ShouldAppendSourceParameter(compactSource))
        {
            parameters.Add($"src={Uri.EscapeDataString(compactSource)}");
        }

        if (publicBaseUrl.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) ||
            publicBaseUrl.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase))
        {
            parameters.Add("ngrok-skip-browser-warning=1");
        }

        var query = parameters.Count == 0 ? string.Empty : "?" + string.Join("&", parameters);
        return $"{publicBaseUrl.TrimEnd('/')}/r/{trackingId}{query}";
    }

    private async Task<bool> IsTrackedUrlResolvableAsync(string trackedUrl, CancellationToken cancellationToken)
    {
        var cacheKey = $"tracked-url-resolvable:{trackedUrl}";
        if (_memoryCache.TryGetValue(cacheKey, out bool cached))
        {
            return cached;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, trackedUrl);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            var valid = (int)response.StatusCode is >= 200 and < 400;
            _memoryCache.Set(cacheKey, valid, TimeSpan.FromMinutes(5));
            return valid;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao validar tracking url {TrackingUrl}.", trackedUrl);
            _memoryCache.Set(cacheKey, false, TimeSpan.FromMinutes(2));
            return false;
        }
    }

    private static string NormalizeTrackingRedirectBaseUrl(string? publicBaseUrl)
    {
        var fallback = (publicBaseUrl ?? string.Empty).Trim().TrimEnd('/');
        if (!Uri.TryCreate(fallback, UriKind.Absolute, out var uri))
        {
            return fallback;
        }

        var authority = uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        if (uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return $"{uri.Scheme}://reidasofertas.ia.br";
        }

        return authority;
    }

    private static string ToTrackingSourceAlias(string? source)
    {
        var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "conversor_web" => "cw",
            "conversor_admin" => "ca",
            "catalogo" => "c",
            "catalogo_site" => "c",
            "telegram" => "tg",
            "whatsapp_grupo" => "wg",
            "whatsapp_dm" => "wd",
            "whatsapp" => "wa",
            _ => normalized
        };
    }

    private static bool ShouldAppendSourceParameter(string compactSource)
    {
        return compactSource is not "wa" and not "wg" and not "wd";
    }

    private static int ResolveTrackingValidityDays(AutomationSettings settings)
    {
        var configured = settings.LinkAutomation?.TrackingLinkValidityDays ?? 4;
        return configured <= 0 ? 4 : Math.Min(configured, 30);
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();
}


