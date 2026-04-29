using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class AffiliateTrackedContentService
{
    private readonly IAffiliateLinkService _affiliateLinkService;
    private readonly TrackingLinkShortenerService _trackingLinkShortener;
    private readonly ILogger<AffiliateTrackedContentService> _logger;

    public AffiliateTrackedContentService(
        IAffiliateLinkService affiliateLinkService,
        TrackingLinkShortenerService trackingLinkShortener,
        ILogger<AffiliateTrackedContentService> logger)
    {
        _affiliateLinkService = affiliateLinkService;
        _trackingLinkShortener = trackingLinkShortener;
        _logger = logger;
    }

    public async Task<string> RewriteAsync(string? text, string originSurface, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text ?? string.Empty;
        }

        var convertedText = await ConvertAffiliateLinksAsync(text, originSurface, cancellationToken);
        return await _trackingLinkShortener.ApplyTrackingAsync(convertedText, originSurface, cancellationToken);
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

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();
}
