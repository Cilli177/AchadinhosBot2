using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class AffiliateTrackedContentService
{
    private readonly IAffiliateLinkService _affiliateLinkService;
    private readonly TrackingLinkShortenerService _trackingLinkShortener;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly ILogger<AffiliateTrackedContentService> _logger;

    public AffiliateTrackedContentService(
        IAffiliateLinkService affiliateLinkService,
        TrackingLinkShortenerService trackingLinkShortener,
        ILinkTrackingStore linkTrackingStore,
        ILogger<AffiliateTrackedContentService> logger)
    {
        _affiliateLinkService = affiliateLinkService;
        _trackingLinkShortener = trackingLinkShortener;
        _linkTrackingStore = linkTrackingStore;
        _logger = logger;
    }

    public async Task<string> RewriteAsync(string? text, string originSurface, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text ?? string.Empty;
        }

        var repairedText = await RepairExistingTrackedLinksAsync(text, originSurface, cancellationToken);
        var convertedText = await ConvertAffiliateLinksAsync(repairedText, originSurface, cancellationToken);
        return await _trackingLinkShortener.ApplyTrackingAsync(convertedText, originSurface, cancellationToken);
    }

    private async Task<string> RepairExistingTrackedLinksAsync(string text, string originSurface, CancellationToken cancellationToken)
    {
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
            var repaired = await RepairTrackedUrlOrKeepAsync(rawUrl, originSurface, cancellationToken);
            rebuilt.Append(repaired);
            rebuilt.Append(trailing);
            cursor = match.Index + match.Length;
        }

        rebuilt.Append(text, cursor, text.Length - cursor);
        return rebuilt.ToString();
    }

    private async Task<string> RepairTrackedUrlOrKeepAsync(string rawUrl, string originSurface, CancellationToken cancellationToken)
    {
        if (!TryExtractOfficialTrackingId(rawUrl, out var trackingId))
        {
            return rawUrl;
        }

        try
        {
            var entry = await _linkTrackingStore.GetLinkAsync(trackingId, cancellationToken);
            var targetUrl = entry?.TargetUrl?.Trim();
            if (string.IsNullOrWhiteSpace(targetUrl) || !ShouldAttemptAffiliateConversion(targetUrl))
            {
                return rawUrl;
            }

            var conversion = await _affiliateLinkService.ConvertAsync(targetUrl, cancellationToken, originSurface, forceResolution: true);
            if (!conversion.Success || string.IsNullOrWhiteSpace(conversion.ConvertedUrl))
            {
                _logger.LogWarning(
                    "Tracking oficial {TrackingId} aponta para target conversivel, mas a reconversao falhou. Target={TargetUrl} Error={Error}",
                    trackingId,
                    targetUrl,
                    conversion.Error ?? conversion.ValidationError ?? "n/a");
                return rawUrl;
            }

            var convertedUrl = conversion.ConvertedUrl.Trim();
            if (string.Equals(convertedUrl, targetUrl, StringComparison.OrdinalIgnoreCase))
            {
                return rawUrl;
            }

            return await _trackingLinkShortener.TrackSingleUrlAsync(convertedUrl, originSurface, cancellationToken, conversion.Store);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao reparar tracking oficial antes do envio. Url={Url} Surface={Surface}", rawUrl, originSurface);
            return rawUrl;
        }
    }

    private async Task<string> ConvertAffiliateLinksAsync(string text, string originSurface, CancellationToken cancellationToken)
    {
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
            var converted = await ConvertUrlOrKeepAsync(rawUrl, originSurface, cancellationToken);
            rebuilt.Append(converted);
            rebuilt.Append(trailing);
            cursor = match.Index + match.Length;
        }

        rebuilt.Append(text, cursor, text.Length - cursor);
        return rebuilt.ToString();
    }

    private async Task<string> ConvertUrlOrKeepAsync(string rawUrl, string originSurface, CancellationToken cancellationToken)
    {
        if (!ShouldAttemptAffiliateConversion(rawUrl))
        {
            return rawUrl;
        }

        try
        {
            var conversion = await _affiliateLinkService.ConvertAsync(rawUrl, cancellationToken, originSurface);
            if (conversion.Success && !string.IsNullOrWhiteSpace(conversion.ConvertedUrl))
            {
                return conversion.ConvertedUrl.Trim();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao converter link afiliado antes do tracking. Url={Url} Surface={Surface}", rawUrl, originSurface);
        }

        return rawUrl;
    }

    private static bool ShouldAttemptAffiliateConversion(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.Trim().Trim('.').ToLowerInvariant();
        var path = uri.AbsolutePath;

        if (host.EndsWith("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (host is "chat.whatsapp.com" or "wa.me" or "api.whatsapp.com")
        {
            return false;
        }

        if (path.StartsWith("/r/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return host.Contains("amazon.", StringComparison.OrdinalIgnoreCase)
            || host is "amzn.to" or "a.co" or "amzlink.to" or "amzn.divulgador.link"
            || host.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
            || host.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
            || host is "meli.la" or "meli.co"
            || host.Contains("shopee", StringComparison.OrdinalIgnoreCase)
            || host is "shp.ee" or "shope.ee"
            || host is "tinyurl.com" or "compre.link" or "bit.ly" or "tiny.one";
    }

    private static bool TryExtractOfficialTrackingId(string? url, out string trackingId)
    {
        trackingId = string.Empty;
        if (!Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase) &&
            !uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var match = Regex.Match(uri.AbsolutePath, @"^/r/([^/?#]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success)
        {
            return false;
        }

        trackingId = Uri.UnescapeDataString(match.Groups[1].Value);
        return !string.IsNullOrWhiteSpace(trackingId);
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();
}
