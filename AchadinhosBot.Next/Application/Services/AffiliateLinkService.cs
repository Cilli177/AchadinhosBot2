using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed class AffiliateLinkService : IAffiliateLinkService
{
    private readonly AffiliateOptions _options;
    private readonly ILogger<AffiliateLinkService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    public AffiliateLinkService(IOptions<AffiliateOptions> options, ILogger<AffiliateLinkService> logger, IHttpClientFactory httpClientFactory)
    {
        _options = options.Value;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    public Task<string?> ConvertAsync(string rawUrl, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return Task.FromResult<string?>(null);
        }

        var host = uri.Host.ToLowerInvariant();
        return ConvertInternalAsync(uri, host, cancellationToken);
    }

    private async Task<string?> ConvertInternalAsync(Uri uri, string host, CancellationToken cancellationToken)
    {
        if (IsAmazonHost(host))
        {
            var amazon = ApplyOrReplaceQuery(RemoveQueryKey(uri, "tag"), "tag", _options.AmazonTag);
            return await ShortenAsync(amazon, cancellationToken);
        }

        if (host.Contains("shein.com"))
        {
            var shein = ApplyOrReplaceQuery(uri, "url_from", _options.SheinId);
            return await ShortenAsync(shein, cancellationToken);
        }

        if (IsMercadoLivreHost(host))
        {
            var ml = await ConvertMercadoLivreAsync(uri, cancellationToken);
            if (!string.IsNullOrWhiteSpace(ml))
            {
                return await ShortenAsync(ml, cancellationToken);
            }
        }

        if (IsShopeeHost(host))
        {
            var shopee = await ConvertShopeeAsync(uri, cancellationToken);
            if (!string.IsNullOrWhiteSpace(shopee))
            {
                return await ShortenAsync(shopee, cancellationToken);
            }
        }

        _logger.LogDebug("Host não suportado para afiliação: {Host}", host);
        return null;
    }

    private static bool IsAmazonHost(string host)
        => host == "amazon.com" || host == "amazon.com.br" || host == "amzn.to" || host.EndsWith(".amazon.com") || host.EndsWith(".amazon.com.br");

    private static bool IsMercadoLivreHost(string host)
        => host.Contains("mercadolivre.com") || host.Contains("mercadolivre.com.br") || host.Contains("mercadolibre.com");

    private static bool IsShopeeHost(string host)
        => host.Contains("shopee.com") || host.Contains("shopee.com.br");

    private async Task<string?> ConvertMercadoLivreAsync(Uri uri, CancellationToken cancellationToken)
    {
        var mlbId = ExtractMercadoLivreId(uri.ToString());
        if (string.IsNullOrWhiteSpace(mlbId))
        {
            mlbId = await ExtractMercadoLivreIdFromHtmlAsync(uri.ToString(), cancellationToken);
        }

        if (string.IsNullOrWhiteSpace(mlbId))
        {
            return null;
        }

        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["matt_tool"] = _options.MercadoLivreMattTool,
            ["matt_word"] = _options.MercadoLivreMattWord
        };

        var url = $"https://produto.mercadolivre.com.br/MLB-{mlbId}";
        var full = ApplyQuery(url, query);
        return full;
    }

    private async Task<string?> ConvertShopeeAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ShopeeAppId) || string.IsNullOrWhiteSpace(_options.ShopeeSecret))
        {
            _logger.LogWarning("Shopee AppId/Secret não configurados");
            return null;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var payload = BuildShopeePayload(uri.ToString());
            if (payload is null)
            {
                _logger.LogWarning("Shopee payload não configurado. Informe a query GraphQL do projeto antigo.");
                return null;
            }

            using var req = new HttpRequestMessage(HttpMethod.Post, "https://open-api.affiliate.shopee.com.br/graphql");
            req.Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var signature = ComputeShopeeSignature(_options.ShopeeAppId, _options.ShopeeSecret, timestamp, payload);
            var authHeader = $"SHA256 Credential={_options.ShopeeAppId}, Timestamp={timestamp}, Signature={signature}";
            req.Headers.TryAddWithoutValidation("Authorization", authHeader);

            var res = await client.SendAsync(req, cancellationToken);
            var body = await res.Content.ReadAsStringAsync(cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                _logger.LogWarning("Shopee GraphQL falhou: {Status} {Body}", res.StatusCode, body);
                return null;
            }

            return ExtractShopeeShortLink(body);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar link Shopee");
            return null;
        }
    }

    private static string? BuildShopeePayload(string url)
    {
        var escapedUrl = JsonEncodedText.Encode(url).ToString();
        var query = $"mutation {{ generateShortLink(input: {{ originUrl: \\\"{escapedUrl}\\\" }}) {{ shortLink }} }}";
        return $"{{\"query\":\"{query}\"}}";
    }

    private static string? ExtractShopeeShortLink(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("data", out var data))
            {
                if (data.TryGetProperty("generateShortLink", out var g)
                    && g.TryGetProperty("shortLink", out var shortLink))
                {
                    return shortLink.GetString();
                }
            }
        }
        catch
        {
            // ignored
        }

        return null;
    }

    private static string ComputeShopeeSignature(string appId, string secret, long timestamp, string bodyJson)
    {
        var raw = $"{appId}{timestamp}{bodyJson}{secret}";
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private async Task<string?> ShortenAsync(string url, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var shortener = $"https://tinyurl.com/api-create.php?url={Uri.EscapeDataString(url)}";
            var res = await client.GetAsync(shortener, cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                _logger.LogWarning("TinyURL falhou: {Status}", res.StatusCode);
                return url;
            }

            var body = await res.Content.ReadAsStringAsync(cancellationToken);
            if (Uri.TryCreate(body.Trim(), UriKind.Absolute, out _))
            {
                return body.Trim();
            }

            return url;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro ao encurtar URL");
            return url;
        }
    }

    private static string ApplyQuery(string url, Dictionary<string, string> pairs)
    {
        var ub = new UriBuilder(url);
        var encodedQuery = string.Join("&", pairs.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        ub.Query = encodedQuery;
        return ub.Uri.ToString();
    }

    private static string ApplyOrReplaceQuery(Uri uri, string key, string value)
    {
        var pairs = ParseQuery(uri.Query);
        pairs[key] = value;

        var encodedQuery = string.Join("&", pairs.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var ub = new UriBuilder(uri)
        {
            Query = encodedQuery
        };

        return ub.Uri.ToString();
    }

    private static Uri RemoveQueryKey(Uri uri, string key)
    {
        var pairs = ParseQuery(uri.Query);
        pairs.Remove(key);
        var encodedQuery = string.Join("&", pairs.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var ub = new UriBuilder(uri)
        {
            Query = encodedQuery
        };
        return ub.Uri;
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return result;
        }

        var clean = query.TrimStart('?');
        foreach (var part in clean.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
            {
                result[Uri.UnescapeDataString(part)] = string.Empty;
                continue;
            }

            var k = Uri.UnescapeDataString(part[..idx]);
            var v = Uri.UnescapeDataString(part[(idx + 1)..]);
            result[k] = v;
        }

        return result;
    }

    private static string? ExtractMercadoLivreId(string text)
    {
        var match = Regex.Match(text, @"MLB-?(\\d{6,})", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    private async Task<string?> ExtractMercadoLivreIdFromHtmlAsync(string url, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var res = await client.GetAsync(url, cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                return null;
            }

            var html = await res.Content.ReadAsStringAsync(cancellationToken);
            return ExtractMercadoLivreId(html);
        }
        catch
        {
            return null;
        }
    }
}
