using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed class AffiliateLinkService : IAffiliateLinkService
{
    private readonly AffiliateOptions _options;
    private readonly ILogger<AffiliateLinkService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private static readonly TimeSpan ExpandCacheTtl = TimeSpan.FromMinutes(10);
    private static readonly ConcurrentDictionary<string, ExpandCacheEntry> ExpandCache = new(StringComparer.OrdinalIgnoreCase);

    public AffiliateLinkService(IOptions<AffiliateOptions> options, ILogger<AffiliateLinkService> logger, IHttpClientFactory httpClientFactory)
    {
        _options = options.Value;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<AffiliateLinkResult> ConvertAsync(string rawUrl, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return new AffiliateLinkResult(false, null, "Unknown", false, null, "URL inválida", false, null);
        }

        var host = uri.Host.ToLowerInvariant();
        return await ConvertWithExpansionAsync(uri, host, cancellationToken);
    }

    private async Task<AffiliateLinkResult> ConvertWithExpansionAsync(Uri uri, string host, CancellationToken cancellationToken)
    {
        var converted = await ConvertInternalAsync(uri, host, cancellationToken);
        if (converted.Success)
        {
            return converted;
        }

        var expanded = await ExpandUrlAsync(uri, cancellationToken);
        if (expanded is null)
        {
            return converted.Error is not null
                ? converted
                : new AffiliateLinkResult(false, null, "Unknown", false, null, "Não foi possível expandir o link", false, null);
        }

        var expandedHost = expanded.Host.ToLowerInvariant();
        if (expandedHost == host && string.Equals(expanded.AbsoluteUri, uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
        {
            return converted.Error is not null
                ? converted
                : new AffiliateLinkResult(false, null, "Unknown", false, null, "Conversão não suportada", false, null);
        }

        return await ConvertInternalAsync(expanded, expandedHost, cancellationToken);
    }

    private async Task<AffiliateLinkResult> ConvertInternalAsync(Uri uri, string host, CancellationToken cancellationToken)
    {
        if (IsAmazonHost(host))
        {
            var resolved = uri;
            if (IsAmazonShortHost(host))
            {
                var expanded = await ExpandAmazonShortAsync(uri, cancellationToken)
                               ?? await ExpandUrlAsync(uri, cancellationToken);
                if (expanded is not null)
                {
                    resolved = expanded;
                }
            }

            var originalQuery = ParseQuery(resolved.Query);
            originalQuery.TryGetValue("tag", out var existingTag);
            var amazon = ApplyOrReplaceQuery(RemoveQueryKey(resolved, "tag"), "tag", _options.AmazonTag);
            var correctionApplied = string.IsNullOrWhiteSpace(existingTag)
                || !string.Equals(existingTag, _options.AmazonTag, StringComparison.OrdinalIgnoreCase);
            var correctionNote = correctionApplied ? $"Tag Amazon corrigida ({existingTag ?? "vazio"} -> {_options.AmazonTag})" : null;

            var validation = await ValidateAffiliateAsync("Amazon", amazon, cancellationToken);
            if (!validation.IsAffiliated)
            {
                _logger.LogWarning("Verificação Amazon falhou após correção. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), amazon, validation.Error);
                return new AffiliateLinkResult(false, null, "Amazon", false, validation.Error, "Link convertido sem afiliado válido", correctionApplied, correctionNote);
            }

            if (correctionApplied)
            {
                _logger.LogWarning("Amazon sem afiliado detectado e corrigido. Original={OriginalUrl} Corrigido={FixedUrl}", uri.ToString(), amazon);
            }

            var shortened = await ShortenAsync(amazon, cancellationToken);
            LogStore("Amazon", uri.ToString(), shortened);
            return new AffiliateLinkResult(true, shortened, "Amazon", true, null, null, correctionApplied, correctionNote);
        }

        if (host.Contains("shein.com"))
        {
            var cleaned = RemoveQueryKeys(uri, SheinRemoveKeys);
            var originalQuery = ParseQuery(cleaned.Query);
            originalQuery.TryGetValue("url_from", out var existingShein);
            var shein = ApplyOrReplaceQuery(cleaned, "url_from", _options.SheinId);
            var correctionApplied = string.IsNullOrWhiteSpace(existingShein)
                || !string.Equals(existingShein, _options.SheinId, StringComparison.OrdinalIgnoreCase);
            var correctionNote = correctionApplied ? $"Shein corrigido ({existingShein ?? "vazio"} -> {_options.SheinId})" : null;

            var validation = await ValidateAffiliateAsync("Shein", shein, cancellationToken);
            if (!validation.IsAffiliated)
            {
                _logger.LogWarning("Verificação Shein falhou após correção. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), shein, validation.Error);
                return new AffiliateLinkResult(false, null, "Shein", false, validation.Error, "Link convertido sem afiliado válido", correctionApplied, correctionNote);
            }

            if (correctionApplied)
            {
                _logger.LogWarning("Shein sem afiliado detectado e corrigido. Original={OriginalUrl} Corrigido={FixedUrl}", uri.ToString(), shein);
            }

            LogStore("Shein", uri.ToString(), shein);
            return new AffiliateLinkResult(true, shein, "Shein", true, null, null, correctionApplied, correctionNote);
        }

        if (IsMercadoLivreHost(host))
        {
            var ml = await ConvertMercadoLivreAsync(uri, cancellationToken);
            if (!string.IsNullOrWhiteSpace(ml))
            {
                var ensured = EnsureMercadoLivreAffiliate(ml, uri.ToString());
                var sanitized = ensured.Url;
                var validation = await ValidateAffiliateAsync("Mercado Livre", sanitized, cancellationToken);
                if (!validation.IsAffiliated)
                {
                    _logger.LogWarning("Verificação Mercado Livre falhou após correção. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), sanitized, validation.Error);
                    return new AffiliateLinkResult(false, null, "Mercado Livre", false, validation.Error, "Link convertido sem afiliado válido", ensured.CorrectionApplied, ensured.CorrectionNote);
                }

                if (ensured.CorrectionApplied)
                {
                    _logger.LogWarning("Mercado Livre sem afiliado detectado e corrigido. Original={OriginalUrl} Corrigido={FixedUrl}", uri.ToString(), sanitized);
                }

                var shortened = await ShortenAsync(sanitized, cancellationToken);
                LogStore("Mercado Livre", uri.ToString(), shortened);
                return new AffiliateLinkResult(true, shortened, "Mercado Livre", true, null, null, ensured.CorrectionApplied, ensured.CorrectionNote);
            }
        }

        if (IsShopeeHost(host))
        {
            var shopee = await ConvertShopeeAsync(uri, cancellationToken);
            if (!string.IsNullOrWhiteSpace(shopee))
            {
                var validation = await ValidateAffiliateAsync("Shopee", shopee, cancellationToken);
                if (!validation.IsAffiliated)
                {
                    _logger.LogWarning("Verificação Shopee falhou. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), shopee, validation.Error);
                    return new AffiliateLinkResult(false, null, "Shopee", false, validation.Error, "Link convertido sem afiliado válido", false, null);
                }

                LogStore("Shopee", uri.ToString(), shopee);
                return new AffiliateLinkResult(true, shopee, "Shopee", true, null, null, false, null);
            }
        }

        _logger.LogDebug("Host não suportado para afiliação: {Host}", host);
        return new AffiliateLinkResult(false, null, "Unknown", false, null, $"Host não suportado: {host}", false, null);
    }

    private static bool IsAmazonHost(string host)
        => host == "amazon.com" || host == "amazon.com.br" || host == "amzn.to" || host.EndsWith(".amazon.com") || host.EndsWith(".amazon.com.br");

    private static bool IsAmazonShortHost(string host)
        => host == "amzn.to" || host == "a.co";

    private static readonly string[] SheinRemoveKeys =
    {
        "url_from",
        "affiliateid",
        "affiliate_id",
        "admitad_uid",
        "click_id",
        "ad_id",
        "adset_id",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content"
    };

    private async Task<Uri?> ExpandAmazonShortAsync(Uri uri, CancellationToken cancellationToken)
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = true,
                CookieContainer = new System.Net.CookieContainer()
            };
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
            client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            using var res = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (res.Headers.Location is null)
            {
                return null;
            }

            var location = res.Headers.Location;
            if (!location.IsAbsoluteUri)
            {
                location = new Uri(uri, location);
            }

            return location;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsMercadoLivreHost(string host)
        => host.Contains("mercadolivre.com") || host.Contains("mercadolivre.com.br") || host.Contains("mercadolibre.com");

    private static bool IsShopeeHost(string host)
        => host.Contains("shopee.com") || host.Contains("shopee.com.br");

    private async Task<string?> ConvertMercadoLivreAsync(Uri uri, CancellationToken cancellationToken)
    {
        var mlbId = ExtractMercadoLivreId(uri.ToString());
        var resolvedUri = uri;
        if (string.IsNullOrWhiteSpace(mlbId))
        {
            var expanded = await ExpandUrlAsync(uri, cancellationToken);
            if (expanded is not null)
            {
                resolvedUri = expanded;
                mlbId = ExtractMercadoLivreId(expanded.ToString());
            }
        }

        if (TryExtractGoUrl(resolvedUri, out var goUri))
        {
            resolvedUri = goUri!;
            if (string.IsNullOrWhiteSpace(mlbId))
            {
                mlbId = ExtractMercadoLivreId(resolvedUri.ToString());
            }
        }

        if (string.IsNullOrWhiteSpace(mlbId))
        {
            if (!string.Equals(resolvedUri.Scheme, "file", StringComparison.OrdinalIgnoreCase))
            {
                mlbId = await ExtractMercadoLivreIdFromHtmlAsync(resolvedUri.ToString(), cancellationToken);
            }
        }

        if (string.IsNullOrWhiteSpace(mlbId))
        {
            if (IsMercadoLivreSocial(resolvedUri.ToString()))
            {
                var productUri = await ExtractMercadoLivreProductLinkFromHtmlAsync(resolvedUri.ToString(), cancellationToken);
                if (productUri is not null)
                {
                    resolvedUri = productUri;
                    if (TryExtractGoUrl(resolvedUri, out var goUriFromSocial))
                    {
                        resolvedUri = goUriFromSocial!;
                    }

                    mlbId = ExtractMercadoLivreId(resolvedUri.ToString());
                    if (string.IsNullOrWhiteSpace(mlbId))
                    {
                        mlbId = await ExtractMercadoLivreIdFromHtmlAsync(resolvedUri.ToString(), cancellationToken);
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(mlbId) && IsMercadoLivreSocial(resolvedUri.ToString()))
            {
                var fallback = CleanMercadoLivreSocial(resolvedUri.ToString());
                var sep = fallback.Contains('?') ? "&" : "?";
                return $"{fallback}{sep}matt_tool={_options.MercadoLivreMattTool}&matt_word={_options.MercadoLivreMattWord}";
            }

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

    private AffiliateCorrectionResult EnsureMercadoLivreAffiliate(string url, string originalUrl)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return new AffiliateCorrectionResult(url, false, null);
        }

        var query = ParseQuery(uri.Query);
        var hasTool = query.TryGetValue("matt_tool", out var tool) && !string.IsNullOrWhiteSpace(tool);
        var hasWord = query.TryGetValue("matt_word", out var word) && !string.IsNullOrWhiteSpace(word);

        if (hasTool && hasWord)
        {
            return new AffiliateCorrectionResult(url, false, null);
        }

        var fixedTool = _options.MercadoLivreMattTool;
        var fixedWord = _options.MercadoLivreMattWord;
        if (string.IsNullOrWhiteSpace(fixedTool) || string.IsNullOrWhiteSpace(fixedWord))
        {
            _logger.LogWarning("Mercado Livre afiliado ausente no link e opções vazias. Original={OriginalUrl}", originalUrl);
            return new AffiliateCorrectionResult(url, false, "Afiliado ausente e opções vazias");
        }

        query["matt_tool"] = fixedTool;
        query["matt_word"] = fixedWord;
        var encodedQuery = string.Join("&", query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var fixedUri = new UriBuilder(uri) { Query = encodedQuery }.Uri.ToString();
        var note = $"Mercado Livre corrigido (matt_tool/matt_word preenchidos)";
        _logger.LogWarning("Mercado Livre sem afiliado detectado e corrigido. Original={OriginalUrl} Corrigido={FixedUrl}", originalUrl, fixedUri);
        return new AffiliateCorrectionResult(fixedUri, true, note);
    }

    private sealed record AffiliateCorrectionResult(string Url, bool CorrectionApplied, string? CorrectionNote);

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

    private static Uri RemoveQueryKeys(Uri uri, IEnumerable<string> keys)
    {
        var pairs = ParseQuery(uri.Query);
        foreach (var key in keys)
        {
            pairs.Remove(key);
        }

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
        var match = Regex.Match(text, @"MLB-?(\d{6,})", RegexOptions.IgnoreCase);
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
            return ExtractMercadoLivreId(html)
                ?? ExtractMercadoLivreIdFromDeepLink(html)
                ?? ExtractMercadoLivreIdFromProductLink(html)
                ?? ExtractMercadoLivreIdFromJson(html);
        }
        catch
        {
            return null;
        }
    }

    private async Task<Uri?> ExtractMercadoLivreProductLinkFromHtmlAsync(string url, CancellationToken cancellationToken)
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

            var direct = Regex.Match(html, "https?://[^\"'\\s>]*mercadolivre[^\"'\\s>]*MLB-?\\d+[^\"'\\s>]*", RegexOptions.IgnoreCase);
            if (direct.Success)
            {
                return new Uri(direct.Value);
            }

            var button = Regex.Match(html, "<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>\\s*Ir\\s+para\\s+produto\\s*</a>", RegexOptions.IgnoreCase);
            if (button.Success)
            {
                var href = WebUtility.HtmlDecode(button.Groups[1].Value);
                return ToAbsolute(url, href);
            }

            var hrefMatch = Regex.Match(html, "href=[\"']([^\"']*MLB-?\\d+[^\"']*)[\"']", RegexOptions.IgnoreCase);
            if (hrefMatch.Success)
            {
                var href = WebUtility.HtmlDecode(hrefMatch.Groups[1].Value);
                return ToAbsolute(url, href);
            }

            var permalink = Regex.Match(html, "\"permalink\"\\s*:\\s*\"(https?:\\\\/\\\\/[^\\\"]+)\"", RegexOptions.IgnoreCase);
            if (permalink.Success)
            {
                var link = permalink.Groups[1].Value.Replace("\\/", "/");
                return new Uri(link);
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static Uri? ToAbsolute(string baseUrl, string href)
    {
        if (string.IsNullOrWhiteSpace(href))
        {
            return null;
        }

        if (Uri.TryCreate(href, UriKind.Absolute, out var absolute))
        {
            return absolute;
        }

        if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
        {
            return new Uri(baseUri, href);
        }

        return null;
    }

    private Task<Uri?> ExpandUrlAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (!IsShortLink(uri.ToString()))
        {
            return Task.FromResult<Uri?>(null);
        }

        if (TryGetCachedExpansion(uri.ToString(), out var cached))
        {
            return Task.FromResult(cached);
        }

        return ExpandUrlRecursiveAsync(uri.ToString(), 0, cancellationToken);
    }

    private async Task<Uri?> ExpandUrlRecursiveAsync(string url, int depth, CancellationToken cancellationToken)
    {
        if (depth > 6)
        {
            return Uri.TryCreate(url, UriKind.Absolute, out var maxUri) ? maxUri : null;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var res = await GetWithRetryAsync(client, url, depth, cancellationToken);
            var resolved = res.RequestMessage?.RequestUri?.ToString() ?? url;

            if (!string.Equals(resolved, url, StringComparison.OrdinalIgnoreCase))
            {
                var expanded = Uri.TryCreate(resolved, UriKind.Absolute, out var redirectUri)
                    ? await ExpandUrlRecursiveAsync(redirectUri.ToString(), depth + 1, cancellationToken)
                    : null;
                CacheExpansion(url, expanded);
                return expanded;
            }

            // If no redirect, try to discover URL in HTML.
            var contentType = res.Content.Headers.ContentType?.MediaType ?? string.Empty;
            if (contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
            {
                var html = await res.Content.ReadAsStringAsync(cancellationToken);
                var discovered = ExtractFirstUrl(html);
                if (Uri.TryCreate(discovered, UriKind.Absolute, out var discoveredUri))
                {
                    var expanded = await ExpandUrlRecursiveAsync(discoveredUri.ToString(), depth + 1, cancellationToken);
                    CacheExpansion(url, expanded);
                    return expanded;
                }
            }

            var final = Uri.TryCreate(resolved, UriKind.Absolute, out var finalUri) ? finalUri : null;
            CacheExpansion(url, final);
            return final;
        }
        catch
        {
            var fallback = Uri.TryCreate(url, UriKind.Absolute, out var finalUri) ? finalUri : null;
            CacheExpansion(url, fallback);
            return fallback;
        }
    }

    private async Task<HttpResponseMessage> GetWithRetryAsync(HttpClient client, string url, int depth, CancellationToken cancellationToken)
    {
        var timeout = IsShortLink(url) ? TimeSpan.FromSeconds(15) : TimeSpan.FromSeconds(30);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        try
        {
            return await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
        }
        catch when (IsShortLink(url) && depth == 0)
        {
            // Retry once for short links.
            using var retryCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            retryCts.CancelAfter(timeout);
            return await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, retryCts.Token);
        }
    }

    private static bool TryGetCachedExpansion(string url, out Uri? uri)
    {
        uri = null;
        if (!ExpandCache.TryGetValue(url, out var entry))
        {
            return false;
        }

        if (DateTimeOffset.UtcNow - entry.Timestamp > ExpandCacheTtl)
        {
            ExpandCache.TryRemove(url, out _);
            return false;
        }

        uri = entry.Uri;
        return true;
    }

    private static void CacheExpansion(string url, Uri? uri)
    {
        ExpandCache[url] = new ExpandCacheEntry(uri, DateTimeOffset.UtcNow);
    }

    private sealed record ExpandCacheEntry(Uri? Uri, DateTimeOffset Timestamp);

    private static string? ExtractFirstUrl(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return null;
        }

        var canonical = Regex.Match(html, "<link[^>]+rel=[\"']canonical[\"'][^>]+href=[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
        if (canonical.Success)
        {
            return canonical.Groups[1].Value;
        }

        var ogUrl = Regex.Match(html, "<meta[^>]+property=[\"']og:url[\"'][^>]+content=[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
        if (ogUrl.Success)
        {
            return ogUrl.Groups[1].Value;
        }

        var ogUrlName = Regex.Match(html, "<meta[^>]+name=[\"']og:url[\"'][^>]+content=[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
        if (ogUrlName.Success)
        {
            return ogUrlName.Groups[1].Value;
        }

        var meta = Regex.Match(html, "http-equiv=[\"']refresh[\"'][^>]*content=[\"'][^\"']*url=([^\"'>]+)", RegexOptions.IgnoreCase);
        if (meta.Success)
        {
            return meta.Groups[1].Value;
        }

        var js = Regex.Match(html, "location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
        if (js.Success)
        {
            return js.Groups[1].Value;
        }

        var replace = Regex.Match(html, "location\\.replace\\(\\s*[\"']([^\"']+)[\"']\\s*\\)", RegexOptions.IgnoreCase);
        if (replace.Success)
        {
            return replace.Groups[1].Value;
        }

        var windowLoc = Regex.Match(html, "window\\.location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
        if (windowLoc.Success)
        {
            return windowLoc.Groups[1].Value;
        }

        var topLoc = Regex.Match(html, "top\\.location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
        if (topLoc.Success)
        {
            return topLoc.Groups[1].Value;
        }

        var link = Regex.Match(html, "https?://[^\\s\"']+", RegexOptions.IgnoreCase);
        return link.Success ? link.Value : null;
    }

    private static string? ExtractMercadoLivreIdFromJson(string html)
    {
        var match = Regex.Match(html, "\"(permalink|canonical)\"\\s*:\\s*\"(https?:\\\\/\\\\/[^\\\"]+)\"", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            var url = match.Groups[2].Value.Replace("\\/", "/");
            return ExtractMercadoLivreId(url);
        }

        return null;
    }

    private static string? ExtractMercadoLivreIdFromDeepLink(string html)
    {
        var match = Regex.Match(html, @"mercadolibre://items/(MLB-?\d+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static string? ExtractMercadoLivreIdFromProductLink(string html)
    {
        var match = Regex.Match(html, @"produto\.mercadolivre\.com\.br\/MLB-?(\d+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static bool IsMercadoLivreSocial(string url)
        => url.Contains("/social/", StringComparison.OrdinalIgnoreCase)
           || url.Contains("/loja/", StringComparison.OrdinalIgnoreCase)
           || url.Contains("/perfil/", StringComparison.OrdinalIgnoreCase)
           || url.Contains("/sec/", StringComparison.OrdinalIgnoreCase);

    private static string CleanMercadoLivreSocial(string url)
    {
        var cleaned = Regex.Replace(url, @"[?&]matt_tool=[^&]+", "", RegexOptions.IgnoreCase);
        cleaned = Regex.Replace(cleaned, @"[?&]matt_word=[^&]+", "", RegexOptions.IgnoreCase);

        if (!cleaned.Contains('?') && cleaned.Contains('&'))
        {
            var idx = cleaned.IndexOf('&');
            cleaned = cleaned[..idx] + "?" + cleaned[(idx + 1)..];
        }

        return cleaned;
    }

    private static bool IsShortLink(string url)
    {
        return url.Contains("amzn.to", StringComparison.OrdinalIgnoreCase)
               || url.Contains("bit.ly", StringComparison.OrdinalIgnoreCase)
               || url.Contains("t.co", StringComparison.OrdinalIgnoreCase)
               || url.Contains("compre.link", StringComparison.OrdinalIgnoreCase)
               || url.Contains("oferta.one", StringComparison.OrdinalIgnoreCase)
               || url.Contains("shp.ee", StringComparison.OrdinalIgnoreCase)
               || url.Contains("shope.ee", StringComparison.OrdinalIgnoreCase)
               || url.Contains("a.co", StringComparison.OrdinalIgnoreCase)
               || url.Contains("tinyurl", StringComparison.OrdinalIgnoreCase)
               || url.Contains("divulgador.link", StringComparison.OrdinalIgnoreCase)
               || url.Contains("mercadolivre.com/sec", StringComparison.OrdinalIgnoreCase)
               || url.Contains("mercadolivre.com.br/sec", StringComparison.OrdinalIgnoreCase)
               || url.Contains("meli.co", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryExtractGoUrl(Uri uri, out Uri? goUri)
    {
        goUri = null;
        var raw = uri.ToString().Replace("&amp;", "&", StringComparison.OrdinalIgnoreCase);
        if (raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
        {
            raw = raw["file://".Length..];
        }
        if (!raw.Contains("/gz/webdevice/config", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var decodedOnce = Uri.UnescapeDataString(raw);
        var idx = decodedOnce.IndexOf("go=", StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return false;
        }

        var goValue = decodedOnce[(idx + 3)..];
        var amp = goValue.IndexOf('&');
        if (amp >= 0)
        {
            goValue = goValue[..amp];
        }

        var decoded = Uri.UnescapeDataString(goValue);
        if (Uri.TryCreate(decoded, UriKind.Absolute, out var parsed))
        {
            goUri = parsed;
            return true;
        }

        return false;
    }

    private void LogStore(string store, string input, string output)
    {
        _logger.LogInformation("{Store} convertido: {Input} => {Output}", store, input, output);
    }

    private async Task<(bool IsAffiliated, string? Error)> ValidateAffiliateAsync(string store, string url, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return (false, "URL convertida inválida");
        }

        var query = ParseQuery(uri.Query);
        (bool IsAffiliated, string? Error) result = store switch
        {
            "Amazon" => query.TryGetValue("tag", out var tag)
                        && string.Equals(tag, _options.AmazonTag, StringComparison.OrdinalIgnoreCase)
                ? (true, null)
                : (false, $"Tag Amazon inválida (esperado: {_options.AmazonTag})"),
            "Mercado Livre" => query.TryGetValue("matt_tool", out var tool)
                                && query.TryGetValue("matt_word", out var word)
                                && string.Equals(tool, _options.MercadoLivreMattTool, StringComparison.OrdinalIgnoreCase)
                                && string.Equals(word, _options.MercadoLivreMattWord, StringComparison.OrdinalIgnoreCase)
                ? (true, null)
                : (false, "Parâmetros Mercado Livre inválidos"),
            "Shein" => query.TryGetValue("url_from", out var shein)
                       && string.Equals(shein, _options.SheinId, StringComparison.OrdinalIgnoreCase)
                ? (true, null)
                : (false, $"Código Shein inválido (esperado: {_options.SheinId})"),
            "Shopee" => (true, null),
            _ => (true, null)
        };

        if (!result.IsAffiliated && IsShortLink(url))
        {
            var expanded = await ExpandUrlAsync(uri, cancellationToken);
            if (expanded is not null && !string.Equals(expanded.ToString(), url, StringComparison.OrdinalIgnoreCase))
            {
                return await ValidateAffiliateAsync(store, expanded.ToString(), cancellationToken);
            }
        }

        return result;
    }
}
