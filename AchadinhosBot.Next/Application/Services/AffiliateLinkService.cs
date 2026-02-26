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
    private readonly IMercadoLivreOAuthService _mercadoLivreOAuthService;
    private readonly ILogger<AffiliateLinkService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private static readonly TimeSpan ExpandCacheTtl = TimeSpan.FromMinutes(10);
    private static readonly ConcurrentDictionary<string, ExpandCacheEntry> ExpandCache = new(StringComparer.OrdinalIgnoreCase);

    public AffiliateLinkService(
        IOptions<AffiliateOptions> options,
        IMercadoLivreOAuthService mercadoLivreOAuthService,
        ILogger<AffiliateLinkService> logger,
        IHttpClientFactory httpClientFactory)
    {
        _options = options.Value;
        _mercadoLivreOAuthService = mercadoLivreOAuthService;
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

            var shortened = await ShortenAsync(amazon, cancellationToken) ?? amazon;
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

        if (IsMercadoLivreHost(host)
            || uri.AbsoluteUri.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
            || uri.AbsoluteUri.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase))
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

                var shortened = await ShortenAsync(sanitized, cancellationToken) ?? sanitized;
                LogStore("Mercado Livre", uri.ToString(), shortened);
                return new AffiliateLinkResult(true, shortened, "Mercado Livre", true, null, null, ensured.CorrectionApplied, ensured.CorrectionNote);
            }

            return new AffiliateLinkResult(
                false,
                null,
                "Mercado Livre",
                false,
                "Produto não identificado",
                "Nao foi possivel identificar um produto valido do Mercado Livre para afiliacao.",
                false,
                null);
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
        => host == "amazon.com"
           || host == "amazon.com.br"
           || host == "amzn.to"
           || host == "amzn.divulgador.link"
           || host.EndsWith(".amazon.com")
           || host.EndsWith(".amazon.com.br");

    private static bool IsAmazonShortHost(string host)
        => host == "amzn.to" || host == "a.co" || host == "amzn.divulgador.link";

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
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        // Remove caracteres invisíveis/estranhos que podem vir de redirecionamentos.
        var normalized = new string(host
            .Trim()
            .ToLowerInvariant()
            .Where(ch => char.IsLetterOrDigit(ch) || ch is '.' or '-')
            .ToArray());

        return normalized.Contains("mercadolivre.com", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("mercadolivre.com.br", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("mercadolibre.com", StringComparison.OrdinalIgnoreCase)
               || normalized.Equals("meli.la", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsShopeeHost(string host)
        => host.Contains("shopee.com")
           || host.Contains("shopee.com.br")
           || host.Contains("shopeemobile.com");

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

        var resolvedUrl = resolvedUri.ToString();
        var isSocialUrl = IsMercadoLivreSocial(resolvedUrl);
        var hasIdInResolvedPath = !string.IsNullOrWhiteSpace(ExtractMercadoLivreId(resolvedUri.AbsolutePath));

        if (string.IsNullOrWhiteSpace(mlbId))
        {
            if (!string.Equals(resolvedUri.Scheme, "file", StringComparison.OrdinalIgnoreCase))
            {
                // Para URLs sociais, não aceitar MLB "solto" do HTML (gera falso positivo).
                mlbId = await ExtractMercadoLivreIdFromHtmlAsync(resolvedUrl, cancellationToken, allowLooseMatch: !isSocialUrl);
            }
        }

        if (!string.IsNullOrWhiteSpace(mlbId) && isSocialUrl && !hasIdInResolvedPath)
        {
            // Garante que links sociais só virem produto quando houver evidência forte.
            mlbId = null;
        }

        if (string.IsNullOrWhiteSpace(mlbId))
        {
            if (isSocialUrl)
            {
                var productUri = await ResolveMercadoLivreProductFromSocialAsync(resolvedUri, cancellationToken);
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
                        mlbId = await ExtractMercadoLivreIdFromHtmlAsync(resolvedUri.ToString(), cancellationToken, allowLooseMatch: false);
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(mlbId))
            {
                return null;
            }
        }

        var itemValidation = await ValidateMercadoLivreItemWithApiAsync(mlbId, cancellationToken);
        if (itemValidation == MercadoLivreItemValidation.Invalid)
        {
            _logger.LogWarning("Mercado Livre item inválido ou não encontrado via API. Id={MlbId} Url={ResolvedUrl}", mlbId, resolvedUri.ToString());
            return null;
        }
        if (itemValidation == MercadoLivreItemValidation.Unknown)
        {
            _logger.LogWarning("Validação de item Mercado Livre inconclusiva via API. Prosseguindo com heurística. Id={MlbId} Url={ResolvedUrl}", mlbId, resolvedUri.ToString());
        }

        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["matt_tool"] = MercadoLivreMattTool,
            ["matt_word"] = MercadoLivreMattWord
        };

        var url = $"https://produto.mercadolivre.com.br/MLB-{mlbId}";
        var full = ApplyQuery(url, query);
        return full;
    }

    private async Task<Uri?> ResolveMercadoLivreProductFromSocialAsync(Uri socialUri, CancellationToken cancellationToken)
    {
        var productUri = await ExtractMercadoLivreProductLinkFromHtmlAsync(socialUri.ToString(), cancellationToken);
        if (productUri is null)
        {
            productUri = await ResolveMercadoLivreProductFromSocialRefAsync(socialUri, cancellationToken);
        }

        if (productUri is null)
        {
            return null;
        }

        return await FollowMercadoLivreProductCandidateAsync(productUri, cancellationToken);
    }

    private async Task<Uri?> FollowMercadoLivreProductCandidateAsync(Uri candidateUri, CancellationToken cancellationToken)
    {
        var current = candidateUri;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            if (TryExtractGoUrl(current, out var goUri) && goUri is not null)
            {
                current = goUri;
            }

            if (IsMercadoLivreProductUri(current))
            {
                return current;
            }

            if (IsMercadoLivreSocial(current.ToString()))
            {
                var nested = await ExtractMercadoLivreProductLinkFromHtmlAsync(current.ToString(), cancellationToken);
                if (nested is not null && !string.Equals(nested.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    current = nested;
                    continue;
                }

                var viaRef = await ResolveMercadoLivreProductFromSocialRefAsync(current, cancellationToken);
                if (viaRef is not null && !string.Equals(viaRef.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    current = viaRef;
                    continue;
                }
            }

            var expanded = await ExpandUrlAsync(current, cancellationToken);
            if (expanded is not null && !string.Equals(expanded.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                current = expanded;
                continue;
            }

            break;
        }

        return IsMercadoLivreProductUri(current) ? current : null;
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

        var fixedTool = MercadoLivreMattTool;
        var fixedWord = MercadoLivreMattWord;
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

    private async Task<Uri?> ResolveMercadoLivreProductFromSocialRefAsync(Uri uri, CancellationToken cancellationToken)
    {
        try
        {
            if (!IsMercadoLivreSocial(uri.ToString()))
            {
                return null;
            }

            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = true,
                CookieContainer = new CookieContainer()
            };
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(20)
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36");
            client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7");

            var current = uri;
            for (var attempt = 0; attempt < 6; attempt++)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, current);
                using var res = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

                if (res.Headers.Location is not null)
                {
                    var next = res.Headers.Location;
                    if (!next.IsAbsoluteUri)
                    {
                        next = new Uri(current, next);
                    }

                    if (TryExtractGoUrl(next, out var goUri) && goUri is not null)
                    {
                        next = goUri;
                    }

                    if (!string.IsNullOrWhiteSpace(ExtractMercadoLivreId(next.ToString())))
                    {
                        return next;
                    }

                    current = next;
                    continue;
                }

                var contentType = res.Content.Headers.ContentType?.MediaType ?? string.Empty;
                if (contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
                {
                    var html = await res.Content.ReadAsStringAsync(cancellationToken);
                    var ctaCandidate = ExtractMercadoLivreUrlNearProductCta(html, current.ToString());
                    if (ctaCandidate is not null)
                    {
                        if (TryExtractGoUrl(ctaCandidate, out var ctaGoUri) && ctaGoUri is not null)
                        {
                            ctaCandidate = ctaGoUri;
                        }

                        if (IsMercadoLivreProductUri(ctaCandidate))
                        {
                            return ctaCandidate;
                        }

                        if (!string.Equals(ctaCandidate.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                        {
                            current = ctaCandidate;
                            continue;
                        }
                    }

                    var bestAnchorHref = FindBestMercadoLivreAnchorHref(html);
                    if (!string.IsNullOrWhiteSpace(bestAnchorHref))
                    {
                        var candidate = ToAbsolute(current.ToString(), bestAnchorHref);
                        if (candidate is not null)
                        {
                            if (TryExtractGoUrl(candidate, out var goUriFromAnchor) && goUriFromAnchor is not null)
                            {
                                candidate = goUriFromAnchor;
                            }

                            if (IsMercadoLivreProductUri(candidate))
                            {
                                return candidate;
                            }

                            if (!string.Equals(candidate.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                current = candidate;
                                continue;
                            }
                        }
                    }

                    var discovered = ExtractFirstUrl(html);
                    if (Uri.TryCreate(discovered, UriKind.Absolute, out var discoveredUri))
                    {
                        if (TryExtractGoUrl(discoveredUri, out var goUriFromHtml) && goUriFromHtml is not null)
                        {
                            discoveredUri = goUriFromHtml;
                        }

                        if (IsMercadoLivreProductUri(discoveredUri))
                        {
                            return discoveredUri;
                        }

                        if (!string.Equals(discoveredUri.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                        {
                            current = discoveredUri;
                            continue;
                        }
                    }
                }

                break;
            }
        }
        catch
        {
            // Best effort only.
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

    private async Task<string?> ExtractMercadoLivreIdFromHtmlAsync(string url, CancellationToken cancellationToken, bool allowLooseMatch = true)
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
            var id = ExtractMercadoLivreIdFromDeepLink(html)
                ?? ExtractMercadoLivreIdFromProductLink(html)
                ?? ExtractMercadoLivreIdFromJson(html);
            if (!string.IsNullOrWhiteSpace(id))
            {
                return id;
            }

            return allowLooseMatch ? ExtractMercadoLivreId(html) : null;
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

            var ctaUrl = ExtractMercadoLivreUrlNearProductCta(html, url);
            if (ctaUrl is not null)
            {
                return ctaUrl;
            }

            var buttonText = Regex.Match(
                html,
                "<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(?:(?!</a>).)*?Ir\\s+para\\s+(?:o\\s+)?produto(?:(?!</a>).)*?</a>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (buttonText.Success)
            {
                var href = WebUtility.HtmlDecode(buttonText.Groups[1].Value);
                var resolved = ToAbsolute(url, href);
                if (resolved is not null)
                {
                    return resolved;
                }
            }

            var buttonAttr = Regex.Match(
                html,
                "<a[^>]+(?:aria-label|title)=[\"'][^\"']*ir\\s+para\\s+(?:o\\s+)?produto[^\"']*[\"'][^>]*href=[\"']([^\"']+)[\"']",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (!buttonAttr.Success)
            {
                buttonAttr = Regex.Match(
                    html,
                    "<a[^>]+href=[\"']([^\"']+)[\"'][^>]*(?:aria-label|title)=[\"'][^\"']*ir\\s+para\\s+(?:o\\s+)?produto[^\"']*[\"']",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);
            }

            if (buttonAttr.Success)
            {
                var href = WebUtility.HtmlDecode(buttonAttr.Groups[1].Value);
                var resolved = ToAbsolute(url, href);
                if (resolved is not null)
                {
                    return resolved;
                }
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

            var bestAnchorHref = FindBestMercadoLivreAnchorHref(html);
            if (!string.IsNullOrWhiteSpace(bestAnchorHref))
            {
                var resolved = ToAbsolute(url, WebUtility.HtmlDecode(bestAnchorHref));
                if (resolved is not null)
                {
                    return resolved;
                }
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static string? FindBestMercadoLivreAnchorHref(string html)
    {
        var anchorMatches = Regex.Matches(
            html,
            "<a\\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);

        string? bestHref = null;
        var bestScore = int.MinValue;
        foreach (Match match in anchorMatches)
        {
            var href = WebUtility.HtmlDecode(match.Groups[1].Value);
            if (string.IsNullOrWhiteSpace(href))
            {
                continue;
            }

            var score = ScoreMercadoLivreAnchorCandidate(href, match.Groups[2].Value);
            if (score > bestScore)
            {
                bestScore = score;
                bestHref = href;
            }
        }

        return bestScore >= 60 ? bestHref : null;
    }

    private static int ScoreMercadoLivreAnchorCandidate(string href, string innerHtml)
    {
        var score = 0;
        var normalizedHref = href.ToLowerInvariant();
        var plainText = Regex.Replace(WebUtility.HtmlDecode(innerHtml), "<.*?>", " ").Trim().ToLowerInvariant();

        if (normalizedHref.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase) ||
            normalizedHref.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
        }

        if (Regex.IsMatch(normalizedHref, @"mlb-?\d{6,}", RegexOptions.IgnoreCase))
        {
            score += 90;
        }

        if (normalizedHref.Contains("/p/", StringComparison.OrdinalIgnoreCase))
        {
            score += 40;
        }

        if (plainText.Contains("ir para o produto", StringComparison.OrdinalIgnoreCase) ||
            plainText.Contains("ir para produto", StringComparison.OrdinalIgnoreCase) ||
            plainText.Contains("ver produto", StringComparison.OrdinalIgnoreCase))
        {
            score += 80;
        }

        if (normalizedHref.Contains("/social/", StringComparison.OrdinalIgnoreCase) ||
            normalizedHref.Contains("/lists", StringComparison.OrdinalIgnoreCase) ||
            normalizedHref.Contains("/loja/", StringComparison.OrdinalIgnoreCase))
        {
            score -= 120;
        }

        return score;
    }

    private static Uri? ExtractMercadoLivreUrlNearProductCta(string html, string baseUrl)
    {
        var decoded = WebUtility.HtmlDecode(html);
        var ctaIndex = FindProductCtaIndex(decoded);
        if (ctaIndex < 0)
        {
            return null;
        }

        Uri? bestCandidate = null;
        var bestScore = int.MinValue;
        foreach (Match match in Regex.Matches(decoded, @"https?:\\\\/\\\\/[^""'<>\s]+|https?://[^""'<>\s]+", RegexOptions.IgnoreCase))
        {
            var rawUrl = match.Value.Replace("\\/", "/", StringComparison.OrdinalIgnoreCase);
            var candidate = ToAbsolute(baseUrl, rawUrl);
            if (candidate is null)
            {
                continue;
            }

            var score = 0;
            if (IsMercadoLivreHost(candidate.Host))
            {
                score += 20;
            }

            if (IsMercadoLivreProductUri(candidate))
            {
                score += 120;
            }

            if (candidate.AbsolutePath.Contains("/p/", StringComparison.OrdinalIgnoreCase))
            {
                score += 35;
            }

            if (IsMercadoLivreSocial(candidate.ToString()))
            {
                score -= 120;
            }

            var distance = Math.Abs(match.Index - ctaIndex);
            if (distance <= 400)
            {
                score += 60;
            }
            else if (distance <= 1200)
            {
                score += 25;
            }

            if (score > bestScore)
            {
                bestScore = score;
                bestCandidate = candidate;
            }
        }

        return bestScore >= 80 ? bestCandidate : null;
    }

    private static int FindProductCtaIndex(string text)
    {
        var patterns = new[]
        {
            "ir para o produto",
            "ir para produto",
            "ver produto"
        };

        foreach (var pattern in patterns)
        {
            var idx = text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                return idx;
            }
        }

        return -1;
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
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var cleanedRaw = Regex.Replace(url, @"[?&](matt_tool|matt_word|ref|forceInApp)=[^&]+", "", RegexOptions.IgnoreCase);
            cleanedRaw = Regex.Replace(cleanedRaw, @"\?&", "?", RegexOptions.IgnoreCase);
            cleanedRaw = Regex.Replace(cleanedRaw, @"&&+", "&", RegexOptions.IgnoreCase);
            cleanedRaw = cleanedRaw.TrimEnd('?', '&');
            return cleanedRaw;
        }

        var query = ParseQuery(uri.Query);
        query.Remove("matt_tool");
        query.Remove("matt_word");
        query.Remove("ref");
        query.Remove("forceInApp");

        var encodedQuery = string.Join("&", query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var ub = new UriBuilder(uri) { Query = encodedQuery };
        return ub.Uri.ToString();
    }

    private static (bool IsAffiliated, string? Error) ValidateShopeeAffiliate(Uri uri, Dictionary<string, string> query)
    {
        var host = uri.Host.ToLowerInvariant();
        var isShopeeDomain = host.Contains("shopee", StringComparison.OrdinalIgnoreCase)
                             || host.Contains("shope.ee", StringComparison.OrdinalIgnoreCase)
                             || host.Contains("shp.ee", StringComparison.OrdinalIgnoreCase);

        if (!isShopeeDomain)
        {
            return (false, "Dominio Shopee invalido para afiliacao.");
        }

        if (HasShopeeAffiliateMarker(query) || IsShopeeShortAffiliateHost(host))
        {
            return (true, null);
        }

        return (false, "Link Shopee sem marcador claro de afiliacao.");
    }

    private static bool HasShopeeAffiliateMarker(Dictionary<string, string> query)
    {
        if (query.Count == 0)
        {
            return false;
        }

        var markerKeys = new[]
        {
            "smtt",
            "uls_trackid",
            "affiliateid",
            "affiliate_id",
            "af_click_lookback",
            "deep_and_deferred"
        };

        foreach (var key in markerKeys)
        {
            if (query.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsShopeeShortAffiliateHost(string host)
        => host.Equals("shp.ee", StringComparison.OrdinalIgnoreCase)
           || host.Equals("shope.ee", StringComparison.OrdinalIgnoreCase)
           || host.Equals("s.shopee.com.br", StringComparison.OrdinalIgnoreCase);

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
               || url.Contains("meli.co", StringComparison.OrdinalIgnoreCase)
               || url.Contains("meli.la", StringComparison.OrdinalIgnoreCase)
               || url.Contains("amzlink.to", StringComparison.OrdinalIgnoreCase);
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

    private async Task<MercadoLivreItemValidation> ValidateMercadoLivreItemWithApiAsync(string mlbId, CancellationToken cancellationToken)
    {
        var numericIdMatch = Regex.Match(mlbId, @"(\d{6,})", RegexOptions.IgnoreCase);
        var numericId = numericIdMatch.Success ? numericIdMatch.Groups[1].Value : null;
        if (string.IsNullOrWhiteSpace(numericId))
        {
            return MercadoLivreItemValidation.Invalid;
        }

        var itemId = $"MLB{numericId}";
        var token = await _mercadoLivreOAuthService.GetAccessTokenAsync(cancellationToken);
        var status = await QueryMercadoLivreItemStatusAsync(itemId, token, cancellationToken);
        if ((status == HttpStatusCode.Unauthorized || status == HttpStatusCode.Forbidden) &&
            !string.IsNullOrWhiteSpace(token))
        {
            status = await QueryMercadoLivreItemStatusAsync(itemId, null, cancellationToken);
        }

        return status switch
        {
            HttpStatusCode.OK => MercadoLivreItemValidation.Valid,
            HttpStatusCode.NotFound => MercadoLivreItemValidation.Invalid,
            HttpStatusCode.Gone => MercadoLivreItemValidation.Invalid,
            HttpStatusCode.BadRequest => MercadoLivreItemValidation.Invalid,
            _ => MercadoLivreItemValidation.Unknown
        };
    }

    private async Task<HttpStatusCode> QueryMercadoLivreItemStatusAsync(string itemId, string? accessToken, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.mercadolibre.com/items/{itemId}");
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            }

            using var res = await client.SendAsync(req, cancellationToken);
            return res.StatusCode;
        }
        catch
        {
            return HttpStatusCode.ServiceUnavailable;
        }
    }

    private enum MercadoLivreItemValidation
    {
        Unknown = 0,
        Valid = 1,
        Invalid = 2
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
            "Mercado Livre" => IsMercadoLivreProductUri(uri)
                                && query.TryGetValue("matt_tool", out var tool)
                                && query.TryGetValue("matt_word", out var word)
                                && string.Equals(tool, MercadoLivreMattTool, StringComparison.OrdinalIgnoreCase)
                                && string.Equals(word, MercadoLivreMattWord, StringComparison.OrdinalIgnoreCase)
                ? (true, null)
                : (false, "Link Mercado Livre invalido (produto nao identificado ou parametros de afiliado ausentes)."),
            "Shein" => query.TryGetValue("url_from", out var shein)
                       && string.Equals(shein, _options.SheinId, StringComparison.OrdinalIgnoreCase)
                ? (true, null)
                : (false, $"Código Shein inválido (esperado: {_options.SheinId})"),
            "Shopee" => ValidateShopeeAffiliate(uri, query),
            _ => (true, null)
        };

        if (result.IsAffiliated &&
            string.Equals(store, "Mercado Livre", StringComparison.OrdinalIgnoreCase) &&
            IsMercadoLivreOAuthRequired())
        {
            var oauth = await _mercadoLivreOAuthService.GetStatusAsync(cancellationToken);
            if (!oauth.Success)
            {
                result = (false, $"OAuth Mercado Livre invÃ¡lido: {oauth.Message}");
            }
        }

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

    private string MercadoLivreMattTool => ResolveString(
        _options.MercadoLivreMattTool,
        ReadEnv("AFFILIATE__MERCADOLIVRE_MATT_TOOL", "AFFILIATE__MERCADOLIVREMATTTOOL", "AFFILIATE__ML_MATT_TOOL"));

    private string MercadoLivreMattWord => ResolveString(
        _options.MercadoLivreMattWord,
        ReadEnv("AFFILIATE__MERCADOLIVRE_MATT_WORD", "AFFILIATE__MERCADOLIVREMATTWORD", "AFFILIATE__ML_MATT_WORD"));

    private bool IsMercadoLivreOAuthRequired()
    {
        if (_options.MercadoLivreRequireOAuth)
        {
            return true;
        }

        var raw = ReadEnv("AFFILIATE__MERCADOLIVRE_REQUIRE_OAUTH", "AFFILIATE__MERCADOLIVREREQUIREOAUTH");
        return bool.TryParse(raw, out var parsed) && parsed;
    }

    private static string ResolveString(params string?[] values)
        => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim() ?? string.Empty;

    private static string? ReadEnv(params string[] keys)
    {
        foreach (var key in keys)
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static bool IsMercadoLivreProductUri(Uri uri)
    {
        var host = uri.Host.ToLowerInvariant();
        var path = uri.AbsolutePath;

        if (host.Contains("produto.mercadolivre", StringComparison.OrdinalIgnoreCase) &&
            Regex.IsMatch(path, @"MLB-?\d{6,}", RegexOptions.IgnoreCase))
        {
            return true;
        }

        if (Regex.IsMatch(path, @"MLB-?\d{6,}", RegexOptions.IgnoreCase))
        {
            return true;
        }

        // Formato canonico curto de produto: /p/MLB123...
        if (Regex.IsMatch(path, @"^/p/[A-Z]{3}\d+", RegexOptions.IgnoreCase))
        {
            return true;
        }

        return false;
    }
}
