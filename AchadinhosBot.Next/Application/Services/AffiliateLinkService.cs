using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Amazon;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed class AffiliateLinkService : IAffiliateLinkService
{
    private readonly AffiliateOptions _options;
    private readonly IMercadoLivreOAuthService _mercadoLivreOAuthService;
    private readonly AmazonCreatorApiClient _amazonCreatorApiClient;
    private readonly AmazonPaApiClient _amazonPaApiClient;
    private readonly ILogger<AffiliateLinkService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private static readonly TimeSpan ExpandCacheTtl = TimeSpan.FromMinutes(10);
    private static readonly ConcurrentDictionary<string, ExpandCacheEntry> ExpandCache = new(StringComparer.OrdinalIgnoreCase);

    public AffiliateLinkService(
        IOptions<AffiliateOptions> options,
        IMercadoLivreOAuthService mercadoLivreOAuthService,
        AmazonCreatorApiClient amazonCreatorApiClient,
        AmazonPaApiClient amazonPaApiClient,
        ILogger<AffiliateLinkService> logger,
        IHttpClientFactory httpClientFactory)
    {
        _options = options.Value;
        _mercadoLivreOAuthService = mercadoLivreOAuthService;
        _amazonCreatorApiClient = amazonCreatorApiClient;
        _amazonPaApiClient = amazonPaApiClient;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<AffiliateLinkResult> ConvertAsync(string rawUrl, CancellationToken cancellationToken, string? source = null)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return new AffiliateLinkResult(false, null, "Unknown", false, null, "URL inválida", false, null);
        }

        var host = NormalizeHost(uri.Host);
        return await ConvertWithExpansionAsync(uri, host, cancellationToken, source);
    }

    private async Task<AffiliateLinkResult> ConvertWithExpansionAsync(Uri uri, string host, CancellationToken cancellationToken, string? source)
    {
        var converted = await ConvertInternalAsync(uri, host, cancellationToken, source);
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

        return await ConvertInternalAsync(expanded, expandedHost, cancellationToken, source);
    }

    private async Task<AffiliateLinkResult> ConvertInternalAsync(Uri uri, string host, CancellationToken cancellationToken, string? source)
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

            var expectedTag = ResolveAmazonPartnerTag();
            if (!IsAmazonPartnerTagValid(expectedTag))
            {
                _logger.LogWarning("Conversao Amazon bloqueada: PartnerTag nao configurada/valida. Original={OriginalUrl}", uri.ToString());
                return new AffiliateLinkResult(
                    false,
                    null,
                    "Amazon",
                    false,
                    "PartnerTag Amazon nao configurada",
                    "Configure a PartnerTag da Amazon para converter links com afiliacao.",
                    false,
                    null);
            }

            var officialErrors = new List<string>();

            var creatorEnabled = false; // bloqueado temporariamente: manter conversao interna sem Creator API

            if (creatorEnabled)
            {
                var creator = await ConvertAmazonWithCreatorApiAsync(resolved, expectedTag, cancellationToken);
                if (creator.Success && !string.IsNullOrWhiteSpace(creator.Url))
                {
                    var creatorValidation = await ValidateAffiliateAsync("Amazon", creator.Url, cancellationToken);
                    if (!creatorValidation.IsAffiliated)
                    {
                        var validationError = creatorValidation.Error ?? "Link Creator API sem validacao de afiliado.";
                        _logger.LogWarning("Verificacao Amazon Creator API falhou. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), creator.Url, validationError);
                        officialErrors.Add($"Creator API: {validationError}");
                    }
                    else
                    {
                        var creatorTagged = ApplyTrackingTags(creator.Url, "Amazon", source);
                        var creatorShort = await ShortenAsync(creatorTagged, cancellationToken) ?? creatorTagged;
                        LogStore("Amazon", uri.ToString(), creatorShort);
                        return new AffiliateLinkResult(true, creatorShort, "Amazon", true, null, null, creator.CorrectionApplied, creator.Note);
                    }
                }
                else
                {
                    var creatorError = creator.Error ?? "Falha sem detalhe.";
                    _logger.LogWarning("Conversao Amazon via Creator API falhou. Original={OriginalUrl} Erro={Error}", uri.ToString(), creatorError);
                    officialErrors.Add($"Creator API: {creatorError}");
                }
            }

            if (_amazonPaApiClient.IsConfigured)
            {
                var official = await ConvertAmazonWithOfficialApiAsync(resolved, cancellationToken);
                if (official.Success && !string.IsNullOrWhiteSpace(official.Url))
                {
                    var officialValidation = await ValidateAffiliateAsync("Amazon", official.Url, cancellationToken);
                    if (!officialValidation.IsAffiliated)
                    {
                        var validationError = officialValidation.Error ?? "Link PA-API sem validacao de afiliado.";
                        _logger.LogWarning("Verificacao Amazon PA-API falhou. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), official.Url, validationError);
                        officialErrors.Add($"PA-API: {validationError}");
                    }
                    else
                    {
                        var officialTagged = ApplyTrackingTags(official.Url, "Amazon", source);
                        var officialShort = await ShortenAsync(officialTagged, cancellationToken) ?? officialTagged;
                        LogStore("Amazon", uri.ToString(), officialShort);
                        return new AffiliateLinkResult(true, officialShort, "Amazon", true, null, null, official.CorrectionApplied, official.Note);
                    }
                }
                else
                {
                    var paError = official.Error ?? "Falha sem detalhe.";
                    _logger.LogWarning("Conversao Amazon via PA-API falhou. Original={OriginalUrl} Erro={Error}", uri.ToString(), paError);
                    officialErrors.Add($"PA-API: {paError}");
                }
            }

            if (officialErrors.Count > 0)
            {
                var errorText = string.Join(" | ", officialErrors.Distinct(StringComparer.OrdinalIgnoreCase));
                return new AffiliateLinkResult(false, null, "Amazon", false, errorText, "Falha na conversao oficial Amazon", false, null);
            }

            var originalQuery = ParseQuery(resolved.Query);
            originalQuery.TryGetValue("tag", out var existingTag);
            var amazon = ApplyOrReplaceQuery(RemoveQueryKey(resolved, "tag"), "tag", expectedTag);
            var correctionApplied = string.IsNullOrWhiteSpace(existingTag)
                || !string.Equals(existingTag, expectedTag, StringComparison.OrdinalIgnoreCase);
            var correctionNote = correctionApplied ? $"Tag Amazon corrigida ({existingTag ?? "vazio"} -> {expectedTag})" : null;

            var validation = await ValidateAffiliateAsync("Amazon", amazon, cancellationToken);
            if (!validation.IsAffiliated)
            {
                _logger.LogWarning("Verificacao Amazon falhou apos correcao. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), amazon, validation.Error);
                return new AffiliateLinkResult(false, null, "Amazon", false, validation.Error, "Link convertido sem afiliado valido", correctionApplied, correctionNote);
            }

            if (correctionApplied)
            {
                _logger.LogWarning("Amazon sem afiliado detectado e corrigido. Original={OriginalUrl} Corrigido={FixedUrl}", uri.ToString(), amazon);
            }

            var taggedAmazon = ApplyTrackingTags(amazon, "Amazon", source);
            var fallbackShort = await ShortenAsync(taggedAmazon, cancellationToken) ?? taggedAmazon;
            LogStore("Amazon", uri.ToString(), fallbackShort);
            return new AffiliateLinkResult(true, fallbackShort, "Amazon", true, null, null, correctionApplied, correctionNote);
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

            var taggedShein = ApplyTrackingTags(shein, "Shein", source);
            LogStore("Shein", uri.ToString(), taggedShein);
            return new AffiliateLinkResult(true, taggedShein, "Shein", true, null, null, correctionApplied, correctionNote);
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

                var taggedMercadoLivre = ApplyTrackingTags(sanitized, "Mercado Livre", source);
                LogStore("Mercado Livre", uri.ToString(), taggedMercadoLivre);
                return new AffiliateLinkResult(true, taggedMercadoLivre, "Mercado Livre", true, null, null, ensured.CorrectionApplied, ensured.CorrectionNote);
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

        if (IsShopeeHost(host) || uri.AbsoluteUri.Contains("shopee", StringComparison.OrdinalIgnoreCase))
        {
            var shopee = await ConvertShopeeAsync(uri, source, cancellationToken);
            if (!string.IsNullOrWhiteSpace(shopee))
            {
                var validation = await ValidateAffiliateAsync("Shopee", shopee, cancellationToken);
                if (!validation.IsAffiliated)
                {
                    _logger.LogWarning("Verificação Shopee falhou. Original={OriginalUrl} Url={Url} Erro={Error}", uri.ToString(), shopee, validation.Error);
                    return new AffiliateLinkResult(false, null, "Shopee", false, validation.Error, "Link convertido sem afiliado válido", false, null);
                }

                var taggedShopee = ApplyTrackingTags(shopee, "Shopee", source);
                LogStore("Shopee", uri.ToString(), taggedShopee);
                return new AffiliateLinkResult(true, taggedShopee, "Shopee", true, null, null, false, null);
            }

            return new AffiliateLinkResult(
                false,
                null,
                "Shopee",
                false,
                "Falha ao gerar link via API Shopee",
                "Verifique ShopeeAppId/ShopeeSecret e assinatura da API oficial da Shopee.",
                false,
                null);
        }

        _logger.LogDebug("Host não suportado para afiliação: {Host}", host);
        return new AffiliateLinkResult(false, null, "Unknown", false, null, $"Host não suportado: {host}", false, null);
    }

    private static bool IsAmazonHost(string host)
    {
        var normalized = NormalizeHost(host);
        return normalized == "amazon.com"
               || normalized == "amazon.com.br"
               || normalized == "amzn.to"
               || normalized == "a.co"
               || normalized == "amzlink.to"
               || normalized == "amzn.divulgador.link"
               || normalized.EndsWith(".amazon.com", StringComparison.OrdinalIgnoreCase)
               || normalized.EndsWith(".amazon.com.br", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAmazonShortHost(string host)
    {
        var normalized = NormalizeHost(host);
        return normalized == "amzn.to"
               || normalized == "a.co"
               || normalized == "amzlink.to"
               || normalized == "amzn.divulgador.link";
    }

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
        var normalized = NormalizeHost(host);

        return normalized.Contains("mercadolivre.com", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("mercadolivre.com.br", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("mercadolibre.com", StringComparison.OrdinalIgnoreCase)
               || normalized.Equals("meli.la", StringComparison.OrdinalIgnoreCase)
               || normalized.Equals("meli.co", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsShopeeHost(string host)
    {
        var normalized = NormalizeHost(host);
        return normalized.Contains("shopee", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("shopee.com", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("shopee.com.br", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains("shopeemobile.com", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return string.Empty;
        }

        var normalized = new string(host
            .Trim()
            .Trim('.')
            .ToLowerInvariant()
            .Where(ch => char.IsLetterOrDigit(ch) || ch is '.' or '-')
            .ToArray());

        return normalized.Trim('.');
    }

    private async Task<string?> ConvertMercadoLivreAsync(Uri uri, CancellationToken cancellationToken)
    {
        var startedFromMercadoLivreShortOrSocial = IsMercadoLivreSocialOrShortUri(uri);
        var mlbId = ExtractPreferredMercadoLivreIdFromUrl(uri.ToString());
        var resolvedUri = uri;
        string? fallbackReason = null;
        if (string.IsNullOrWhiteSpace(mlbId))
        {
            var expanded = await ExpandUrlAsync(uri, cancellationToken);
            if (expanded is not null)
            {
                resolvedUri = expanded;
                mlbId = ExtractPreferredMercadoLivreIdFromUrl(expanded.ToString());
            }
        }

        if (string.IsNullOrWhiteSpace(mlbId))
        {
            var chainedExpansion = await ExpandMercadoLivreChainAsync(resolvedUri, cancellationToken);
            if (chainedExpansion is not null)
            {
                resolvedUri = chainedExpansion;
                mlbId = ExtractPreferredMercadoLivreIdFromUrl(resolvedUri.ToString());
            }
        }

        if (TryExtractGoUrl(resolvedUri, out var goUri))
        {
            resolvedUri = goUri!;
            if (string.IsNullOrWhiteSpace(mlbId))
            {
                mlbId = ExtractPreferredMercadoLivreIdFromUrl(resolvedUri.ToString());
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

                    mlbId = ExtractPreferredMercadoLivreIdFromUrl(resolvedUri.ToString());
                    if (string.IsNullOrWhiteSpace(mlbId))
                    {
                        mlbId = await ExtractMercadoLivreIdFromHtmlAsync(resolvedUri.ToString(), cancellationToken, allowLooseMatch: false);
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(mlbId))
            {
                if (isSocialUrl)
                {
                    _logger.LogInformation("Mercado Livre: Vitrine detectada (sem MLB-ID). Prosseguindo com afiliação da URL social. Resolved={ResolvedUrl}", resolvedUrl);
                    return BuildMercadoLivreAffiliateUrl(null, resolvedUrl);
                }

                if (startedFromMercadoLivreShortOrSocial || IsMercadoLivreSocialOrShortUri(resolvedUri))
                {
                    _logger.LogWarning(
                        "Mercado Livre: link social/curto sem MLB-ID confiavel. Conversao abortada para evitar link invalido. Original={OriginalUrl} Resolved={ResolvedUrl}",
                        uri.ToString(),
                        resolvedUri.ToString());
                    return null;
                }

                return null;
            }
        }

        // Validação via API desativada temporariamente. Motivo: a URL canônica retornada 
        // frequentemente aponta para o domínio incorreto (produto.mercadolivre.com.br) 
        // para IDs curtos (catálogos), gerando erros 404 intermitentes nas pontas.
        // Toda a conversão confiará apenas na lógica interna de BuildMercadoLivreAffiliateUrl.
        string? canonicalUrl = null;

        _logger.LogInformation(
            "Mercado Livre: Validacao de API desativada. Aplicando fallback manual local. Original={OriginalUrl} Resolved={ResolvedUrl} Id={MlbId}",
            uri.ToString(),
            resolvedUri.ToString(),
            mlbId);

        return BuildMercadoLivreAffiliateUrl(mlbId, canonicalUrl);
    }

    private bool CanUseMercadoLivreManualFallback(Uri originalUri, Uri resolvedUri, string? mlbId)
    {
        if (string.IsNullOrWhiteSpace(mlbId))
        {
            return false;
        }

        if (IsMercadoLivreProductUri(resolvedUri))
        {
            return true;
        }

        if (!IsMercadoLivreSocialOrShortUri(originalUri) && !IsMercadoLivreSocialOrShortUri(resolvedUri))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(ExtractMercadoLivreId(resolvedUri.AbsolutePath))
               || !string.IsNullOrWhiteSpace(ExtractPreferredMercadoLivreIdFromUrl(resolvedUri.ToString()));
    }

    private string BuildMercadoLivreAffiliateUrl(string? mlbId, string? canonicalUrl)
    {
        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["matt_tool"] = MercadoLivreMattTool,
            ["matt_word"] = MercadoLivreMattWord
        };

        string? url;
        if (!string.IsNullOrWhiteSpace(canonicalUrl))
        {
            url = canonicalUrl;
        }
        else if (!string.IsNullOrWhiteSpace(mlbId))
        {
            var numericPart = mlbId.ToUpperInvariant().Replace("MLB", "").Replace("-", "");
            // Catalog/product IDs have ≤8 digits and use /p/MLBxxxxxxxx format.
            // Item IDs have 10+ digits and use produto.mercadolivre.com.br/MLB-xxxxxxxxxx format.
            if (numericPart.Length <= 8)
            {
                url = $"https://www.mercadolivre.com.br/p/MLB{numericPart}";
            }
            else
            {
                url = $"https://produto.mercadolivre.com.br/MLB-{numericPart}";
            }
        }
        else
        {
            url = null;
        }

        if (string.IsNullOrWhiteSpace(url))
        {
            return string.Empty;
        }

        return ApplyQuery(url, query);
    }


    private async Task<string?> TryRecoverMercadoLivreIdAsync(Uri originalUri, Uri resolvedUri, string invalidMlbId, CancellationToken cancellationToken)
    {
        var candidateIds = new List<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddId(string? id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                return;
            }

            if (id.Equals(invalidMlbId, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (!candidateIds.Contains(id, StringComparer.OrdinalIgnoreCase))
            {
                candidateIds.Add(id);
            }
        }

        async Task HarvestFromUriAsync(Uri? candidateUri)
        {
            if (candidateUri is null)
            {
                return;
            }

            var raw = candidateUri.ToString();
            if (!visited.Add(raw))
            {
                return;
            }

            AddId(ExtractMercadoLivreId(raw));
            AddId(ExtractPreferredMercadoLivreIdFromUrl(raw));
            AddId(ExtractMercadoLivreId(candidateUri.AbsolutePath));

            if (TryExtractGoUrl(candidateUri, out var goUri) && goUri is not null)
            {
                AddId(ExtractMercadoLivreId(goUri.ToString()));
                AddId(ExtractPreferredMercadoLivreIdFromUrl(goUri.ToString()));
            }

            var expanded = await ExpandMercadoLivreChainAsync(candidateUri, cancellationToken);
            if (expanded is not null && visited.Add(expanded.ToString()))
            {
                AddId(ExtractMercadoLivreId(expanded.ToString()));
                AddId(ExtractPreferredMercadoLivreIdFromUrl(expanded.ToString()));
                AddId(ExtractMercadoLivreId(expanded.AbsolutePath));
            }

            var pageIdStrict = await ExtractMercadoLivreIdFromHtmlAsync(raw, cancellationToken, allowLooseMatch: false);
            AddId(pageIdStrict);

            var pageIdLoose = await ExtractMercadoLivreIdFromHtmlAsync(raw, cancellationToken, allowLooseMatch: true);
            AddId(pageIdLoose);

            var socialResolved = await ResolveMercadoLivreProductFromSocialAsync(candidateUri, cancellationToken);
            if (socialResolved is not null)
            {
                AddId(ExtractMercadoLivreId(socialResolved.ToString()));
                AddId(ExtractPreferredMercadoLivreIdFromUrl(socialResolved.ToString()));
                AddId(ExtractMercadoLivreId(socialResolved.AbsolutePath));
            }
        }

        await HarvestFromUriAsync(originalUri);
        await HarvestFromUriAsync(resolvedUri);

        foreach (var candidateId in candidateIds)
        {
            var validation = await ValidateMercadoLivreItemWithApiAsync(candidateId, cancellationToken);
            if (validation == MercadoLivreItemValidation.Valid)
            {
                return candidateId;
            }
        }

        return null;
    }

    private async Task<Uri?> ExpandMercadoLivreChainAsync(Uri seedUri, CancellationToken cancellationToken)
    {
        var current = seedUri;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            if (TryExtractGoUrl(current, out var goUri) && goUri is not null)
            {
                current = goUri;
            }

            if (!string.IsNullOrWhiteSpace(ExtractPreferredMercadoLivreIdFromUrl(current.ToString())))
            {
                return current;
            }

            var expanded = await ExpandUrlAsync(current, cancellationToken);
            if (expanded is null || string.Equals(expanded.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                expanded = await ExpandUrlRecursiveAsync(current.ToString(), 0, cancellationToken);
            }

            if (expanded is null || string.Equals(expanded.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                return current;
            }

            current = expanded;
        }

        return current;
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
        for (var attempt = 0; attempt < 10; attempt++)
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

    private async Task<string?> ConvertShopeeAsync(Uri uri, string? source, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ShopeeAppId) || string.IsNullOrWhiteSpace(_options.ShopeeSecret))
        {
            _logger.LogWarning("Shopee AppId/Secret não configurados");
            return null;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var subIds = ResolveShopeeSubIds(source);
            var payload = BuildShopeePayload(uri.ToString(), subIds);
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
            var shortLink = ExtractShopeeShortLink(body);
            if (!string.IsNullOrWhiteSpace(shortLink))
            {
                return shortLink;
            }

            if (ContainsShopeeInvalidSubIdError(body))
            {
                var fallbackPayload = BuildShopeePayload(uri.ToString(), Array.Empty<string>());
                if (!string.IsNullOrWhiteSpace(fallbackPayload))
                {
                    using var retryReq = new HttpRequestMessage(HttpMethod.Post, "https://open-api.affiliate.shopee.com.br/graphql");
                    retryReq.Content = new StringContent(fallbackPayload, System.Text.Encoding.UTF8, "application/json");
                    var retryTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    var retrySignature = ComputeShopeeSignature(_options.ShopeeAppId, _options.ShopeeSecret, retryTimestamp, fallbackPayload);
                    var retryAuthHeader = $"SHA256 Credential={_options.ShopeeAppId}, Timestamp={retryTimestamp}, Signature={retrySignature}";
                    retryReq.Headers.TryAddWithoutValidation("Authorization", retryAuthHeader);

                    var retryRes = await client.SendAsync(retryReq, cancellationToken);
                    var retryBody = await retryRes.Content.ReadAsStringAsync(cancellationToken);
                    if (retryRes.IsSuccessStatusCode)
                    {
                        var retryShortLink = ExtractShopeeShortLink(retryBody);
                        if (!string.IsNullOrWhiteSpace(retryShortLink))
                        {
                            _logger.LogWarning("Shopee retornou invalid sub id; conversao refeita sem subIds.");
                            return retryShortLink;
                        }
                    }
                }
            }

            _logger.LogWarning("Shopee GraphQL sem shortLink no retorno: {Body}", body);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar link Shopee");
            return null;
        }
    }

    private static string? BuildShopeePayload(string url, IReadOnlyList<string> subIds)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var escapedUrl = EscapeGraphQlString(url.Trim());
        var sanitizedSubIds = subIds
            .Where(static id => !string.IsNullOrWhiteSpace(id))
            .Select(static id => EscapeGraphQlString(id.Trim()))
            .Take(5)
            .ToArray();
        var subIdsLiteral = sanitizedSubIds.Length == 0
            ? string.Empty
            : $", subIds: [{string.Join(", ", sanitizedSubIds.Select(id => $"\"{id}\""))}]";
        var query = $"mutation {{ generateShortLink(input: {{ originUrl: \"{escapedUrl}\"{subIdsLiteral} }}) {{ shortLink }} }}";
        return JsonSerializer.Serialize(new { query });
    }

    private static string EscapeGraphQlString(string value)
        => value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);

    private static IReadOnlyList<string> ResolveShopeeSubIds(string? source)
    {
        var normalizedSource = NormalizeShopeeSubIdValue(source, "conversorweb");
        var entryPoint = NormalizeShopeeSubIdValue(ResolveTrackingEntryPoint(source), "conversorweb");
        var channel = NormalizeShopeeSubIdValue(ResolveTrackingChannel(source), "conversor");
        var surface = NormalizeShopeeSubIdValue(ResolveTrackingSurface(source), "site");
        var flow = NormalizeShopeeSubIdValue(ResolveTrackingFlow(source), "direct");
        return new[] { normalizedSource, entryPoint, channel, surface, flow };
    }

    private static string ResolveTrackingChannel(string? source)
    {
        var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
        if (normalized.Contains("whatsapp", StringComparison.Ordinal))
        {
            return "whatsapp";
        }

        if (normalized.Contains("telegram", StringComparison.Ordinal))
        {
            return "telegram";
        }

        if (normalized.Contains("instagram", StringComparison.Ordinal))
        {
            return "instagram";
        }

        if (normalized.Contains("catalog", StringComparison.Ordinal))
        {
            return "catalogo";
        }

        return "conversor";
    }

    private static string ResolveTrackingSurface(string? source)
    {
        var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
        if (normalized.Contains("grupo", StringComparison.Ordinal))
        {
            return "grupo";
        }

        if (normalized.Contains("dm", StringComparison.Ordinal) || normalized.Contains("manual", StringComparison.Ordinal))
        {
            return "dm";
        }

        if (normalized.Contains("story", StringComparison.Ordinal))
        {
            return "story";
        }

        if (normalized.Contains("post", StringComparison.Ordinal))
        {
            return "post";
        }

        return "site";
    }

    private static string ResolveTrackingFlow(string? source)
    {
        var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
        if (normalized.Contains("crosspost", StringComparison.Ordinal) || normalized.Contains("forward", StringComparison.Ordinal))
        {
            return "crosspost";
        }

        if (normalized.Contains("catalog", StringComparison.Ordinal))
        {
            return "catalog_sync";
        }

        return "direct";
    }

    private static string NormalizeShopeeSubIdValue(string? value, string fallback)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return fallback;
        }

        normalized = Regex.Replace(normalized, @"[^a-z0-9]+", "_");
        normalized = Regex.Replace(normalized, @"_+", "_").Trim('_');
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return fallback;
        }

        return normalized.Length <= 32 ? normalized : normalized[..32];
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
                    var best = ExtractBestUrlFromHtml(html, current.ToString())
                               ?? (Uri.TryCreate(discovered, UriKind.Absolute, out var discoveredUriOld) ? discoveredUriOld : null);
                    if (best is not null)
                    {
                        var discoveredUri = best;
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
        if (string.IsNullOrWhiteSpace(url))
        {
            return url;
        }

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
        if (string.IsNullOrWhiteSpace(url)) return url;
        
        var ub = new UriBuilder(url);
        var query = ParseQuery(ub.Query);
        
        foreach (var pair in pairs)
        {
            query[pair.Key] = pair.Value;
        }

        var encodedQuery = string.Join("&", query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
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
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        static string? MatchId(string input)
        {
            var match = Regex.Match(input, @"(MLB-?\d{6,})", RegexOptions.IgnoreCase);
            if (!match.Success) return null;
            var id = match.Groups[1].Value.ToUpperInvariant();
            if (id.Contains("-")) id = id.Replace("-", "");
            return id;
        }

        var direct = MatchId(text);
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        var htmlDecoded = WebUtility.HtmlDecode(text);
        if (!string.Equals(htmlDecoded, text, StringComparison.Ordinal))
        {
            var htmlDecodedId = MatchId(htmlDecoded);
            if (!string.IsNullOrWhiteSpace(htmlDecodedId))
            {
                return htmlDecodedId;
            }
        }

        var unescapedOnce = TryUnescapeUrlComponent(htmlDecoded);
        if (!string.IsNullOrWhiteSpace(unescapedOnce))
        {
            var unescapedOnceId = MatchId(unescapedOnce);
            if (!string.IsNullOrWhiteSpace(unescapedOnceId))
            {
                return unescapedOnceId;
            }

            var unescapedTwice = TryUnescapeUrlComponent(unescapedOnce);
            if (!string.IsNullOrWhiteSpace(unescapedTwice))
            {
                var unescapedTwiceId = MatchId(unescapedTwice);
                if (!string.IsNullOrWhiteSpace(unescapedTwiceId))
                {
                    return unescapedTwiceId;
                }
            }
        }

        return null;
    }

    private static bool ContainsShopeeInvalidSubIdError(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        return json.Contains("invalid sub id", StringComparison.OrdinalIgnoreCase);
    }

    private static string? ExtractPreferredMercadoLivreIdFromUrl(string rawUrl)
    {
        if (string.IsNullOrWhiteSpace(rawUrl))
        {
            return null;
        }

        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return ExtractMercadoLivreId(rawUrl);
        }

        var query = ParseQuery(uri.Query);
        if (query.TryGetValue("wid", out var wid))
        {
            var id = ExtractMercadoLivreId(wid);
            if (!string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        if (query.TryGetValue("item_id", out var itemId))
        {
            var id = ExtractMercadoLivreId(itemId);
            if (!string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        if (query.TryGetValue("pdp_filters", out var filters))
        {
            var decodedFilters = WebUtility.HtmlDecode(filters);
            var filterItem = Regex.Match(decodedFilters, @"item_id[:=](MLB-?\d{6,})", RegexOptions.IgnoreCase);
            if (filterItem.Success)
            {
                return ExtractMercadoLivreId(filterItem.Groups[1].Value);
            }

            var filterFallback = ExtractMercadoLivreId(decodedFilters);
            if (!string.IsNullOrWhiteSpace(filterFallback))
            {
                return filterFallback;
            }
        }

        var pathId = ExtractMercadoLivreId(uri.AbsolutePath);
        if (!string.IsNullOrWhiteSpace(pathId))
        {
            return pathId;
        }

        return ExtractMercadoLivreId(uri.ToString());
    }

    private static string? TryUnescapeUrlComponent(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch
        {
            return null;
        }
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

            _logger.LogInformation("[ML Social] HTML Length: {Length}", html?.Length ?? 0);

            // 1. Try to extract the Action Link (Ir para produto) which is the most reliable for social pages
            // The user provided the exact HTML pattern for this button
            var actionLinkMatch = Regex.Match(
                html,
                "<a[^>]+href=[\"'](https?://(?:[^\"]+mercadolivre\\.com\\.br[^\"]+MLB-?\\d+[^\"]*|[^\"]+meli\\.la[^\"]+))[\"'][^>]*class=[\"'][^\"']*poly-component__link--action-link[^\"']*[\"']",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);
            
            if (actionLinkMatch.Success)
            {
                var featUrl = WebUtility.HtmlDecode(actionLinkMatch.Groups[1].Value.Replace("\\u002F", "/"));
                _logger.LogInformation("[ML Social] Targeted PRIMARY product via action-link: {Url}", featUrl);
                if (Uri.TryCreate(featUrl, UriKind.Absolute, out var result))
                {
                    return result;
                }
            }

            // 2. Fallback: card-featured container JSON
            var featuredMatch = Regex.Match(html, "\"id\"\\s*:\\s*\"card-featured\".*?\"url\"\\s*:\\s*\"(https?://(?:[^\"]+mercadolivre\\.com\\.br[^\"]+MLB-?\\d+|[^\"]+meli\\.la[^\"]+))\"", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (featuredMatch.Success)
            {
                var featUrl = WebUtility.HtmlDecode(featuredMatch.Groups[1].Value.Replace("\\u002F", "/"));
                _logger.LogInformation("[ML Social] Targeted product via card-featured JSON: {Url}", featUrl);
                if (Uri.TryCreate(featUrl, UriKind.Absolute, out var result)) return result;
            }

            // 3. Fallback: Meta Tag check
            var ogTitleMatch = Regex.Match(html, "<meta\\s+property=[\"']og:title[\"']\\s+content=[\"']([^\"']+)[\"']", RegexOptions.IgnoreCase);
            if (ogTitleMatch.Success)
            {
                _logger.LogInformation("[ML Social] Meta title: {Title}", ogTitleMatch.Groups[1].Value);
                if (ogTitleMatch.Groups[1].Value.Contains("Whey", StringComparison.OrdinalIgnoreCase) || ogTitleMatch.Groups[1].Value.Contains("FTW", StringComparison.OrdinalIgnoreCase))
                {
                    var anyMlbMatch = Regex.Match(html, "\"url\"\\s*:\\s*\"(https?://[^\"]+mercadolivre\\.com\\.br/[^\"]+MLB-?\\d+[^\"]*)\"", RegexOptions.IgnoreCase);
                    if (anyMlbMatch.Success)
                    {
                        var fallbackUrl = WebUtility.HtmlDecode(anyMlbMatch.Groups[1].Value.Replace("\\u002F", "/"));
                        if (Uri.TryCreate(fallbackUrl, UriKind.Absolute, out var result)) return result;
                    }
                }
            }

            var jsonProductMatch = Regex.Match(
                html,
                "\"id\"\\s*:\\s*\"show_product\"\\s*,\\s*\"text\"\\s*:\\s*\"Ir\\s+para\\s+(?:o\\s+)?produto\"\\s*,\\s*\"url\"\\s*:\\s*\"([^\"]+)\"",
                RegexOptions.IgnoreCase);
            
            if (jsonProductMatch.Success)
            {
                var jsonUrl = WebUtility.HtmlDecode(jsonProductMatch.Groups[1].Value.Replace("\\u002F", "/"));
                _logger.LogInformation("[ML Social] Found show_product button URL: {Url}", jsonUrl);
                if (Uri.TryCreate(jsonUrl, UriKind.Absolute, out var result))
                {
                    return result;
                }
            }

            var socialAction = Regex.Match(
                html,
                "<a[^>]+class=[\"'][^\"']*poly-component__link--action-link[^\"']*[\"'][^>]*href=[\"']([^\"']+)[\"']",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);
            
            if (socialAction.Success)
            {
                var href = WebUtility.HtmlDecode(socialAction.Groups[1].Value);
                var resolved = ToAbsolute(url, href);
                if (resolved is not null)
                {
                    return resolved;
                }
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

            var direct = Regex.Match(html, "https?://[^\"'\\s>]*mercadolivre[^\"'\\s>]*MLB-?\\d+[^\"'\\s>]*", RegexOptions.IgnoreCase);
            if (direct.Success)
            {
                return new Uri(direct.Value);
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
            if (plainText.Contains("ir para produto", StringComparison.OrdinalIgnoreCase) ||
                plainText.Contains("ir para o produto", StringComparison.OrdinalIgnoreCase))
            {
                score += 50; // Compensate for social penalty if it's the CTA button
            }
            else
            {
                score -= 120;
            }
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

        return ExpandUrlSmartAsync(uri, cancellationToken);
    }

    private async Task<Uri?> ExpandUrlSmartAsync(Uri uri, CancellationToken cancellationToken)
    {
        var smart = await ExpandShortLinkWithRedirectHintsAsync(uri, cancellationToken);
        if (smart is not null)
        {
            CacheExpansion(uri.ToString(), smart);
            return smart;
        }

        return await ExpandUrlRecursiveAsync(uri.ToString(), 0, cancellationToken);
    }

    private async Task<Uri?> ExpandShortLinkWithRedirectHintsAsync(Uri uri, CancellationToken cancellationToken)
    {
        try
        {
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
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
            client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7");

            var current = uri;
            Uri? bestCandidate = null;
            for (var attempt = 0; attempt < 8; attempt++)
            {
                bestCandidate = PreferBestCandidate(bestCandidate, current);
                if (IsStrongAffiliateCandidate(current))
                {
                    return current;
                }

                HttpResponseMessage res;
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, current);
                    res = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                }
                catch
                {
                    break;
                }

                using (res)
                {
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

                        bestCandidate = PreferBestCandidate(bestCandidate, next);
                        if (IsStrongAffiliateCandidate(next) || IsMercadoLivreSocial(next.ToString()))
                        {
                            return next;
                        }

                        if (!string.Equals(next.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                        {
                            current = next;
                            continue;
                        }
                    }

                    var contentType = res.Content.Headers.ContentType?.MediaType ?? string.Empty;
                    if (contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
                    {
                        var html = await res.Content.ReadAsStringAsync(cancellationToken);
                        var discovered = ExtractBestUrlFromHtml(html, current.ToString());
                        if (discovered is not null)
                        {
                            if (TryExtractGoUrl(discovered, out var discoveredGoUri) && discoveredGoUri is not null)
                            {
                                discovered = discoveredGoUri;
                            }

                            bestCandidate = PreferBestCandidate(bestCandidate, discovered);
                            if (IsStrongAffiliateCandidate(discovered) || IsMercadoLivreSocial(discovered.ToString()))
                            {
                                return discovered;
                            }

                            if (!string.Equals(discovered.ToString(), current.ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                current = discovered;
                                continue;
                            }
                        }
                    }

                    var requestUri = res.RequestMessage?.RequestUri;
                    if (requestUri is not null)
                    {
                        bestCandidate = PreferBestCandidate(bestCandidate, requestUri);
                        if (IsStrongAffiliateCandidate(requestUri))
                        {
                            return requestUri;
                        }
                    }
                }

                break;
            }

            return bestCandidate;
        }
        catch
        {
            return null;
        }
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
                var discoveredUri = ExtractBestUrlFromHtml(html, url);
                if (discoveredUri is not null)
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

    private static Uri? ExtractBestUrlFromHtml(string html, string baseUrl)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return null;
        }

        var candidates = new List<string>();
        void AddMatch(string pattern)
        {
            foreach (Match match in Regex.Matches(html, pattern, RegexOptions.IgnoreCase))
            {
                if (match.Groups.Count > 1)
                {
                    candidates.Add(WebUtility.HtmlDecode(match.Groups[1].Value));
                }
                else if (match.Success)
                {
                    candidates.Add(WebUtility.HtmlDecode(match.Value));
                }
            }
        }

        AddMatch("<link[^>]+rel=[\"']canonical[\"'][^>]+href=[\"']([^\"']+)[\"']");
        AddMatch("<meta[^>]+property=[\"']og:url[\"'][^>]+content=[\"']([^\"']+)[\"']");
        AddMatch("<meta[^>]+name=[\"']og:url[\"'][^>]+content=[\"']([^\"']+)[\"']");
        AddMatch("http-equiv=[\"']refresh[\"'][^>]*content=[\"'][^\"']*url=([^\"'>]+)");
        AddMatch("location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']");
        AddMatch("location\\.replace\\(\\s*[\"']([^\"']+)[\"']\\s*\\)");
        AddMatch("window\\.location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']");
        AddMatch("top\\.location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']");
        AddMatch("https?://[^\\s\"'<>]+");

        Uri? best = null;
        var bestScore = int.MinValue;
        foreach (var candidateRaw in candidates)
        {
            var candidate = ToAbsolute(baseUrl, candidateRaw);
            if (candidate is null)
            {
                continue;
            }

            if (TryExtractGoUrl(candidate, out var goUri) && goUri is not null)
            {
                candidate = goUri;
            }

            var score = ScoreAffiliateCandidate(candidate);
            if (score > bestScore)
            {
                bestScore = score;
                best = candidate;
            }
        }

        return bestScore > 0 ? best : null;
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
        var match = Regex.Match(html, @"produto\.mercadolivre\.com\.br\/(MLB-?\d+)", RegexOptions.IgnoreCase);
        if (!match.Success) return null;
        var id = match.Groups[1].Value.ToUpperInvariant();
        if (id.Contains("-")) id = id.Replace("-", "");
        return id;
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

    private static bool IsStrongAffiliateCandidate(Uri uri)
        => ScoreAffiliateCandidate(uri) >= 80;

    private static Uri PreferBestCandidate(Uri? current, Uri candidate)
    {
        if (current is null)
        {
            return candidate;
        }

        return ScoreAffiliateCandidate(candidate) > ScoreAffiliateCandidate(current)
            ? candidate
            : current;
    }

    private static int ScoreAffiliateCandidate(Uri uri)
    {
        var score = 0;
        var host = NormalizeHost(uri.Host);
        var url = uri.ToString();
        var path = uri.AbsolutePath ?? string.Empty;
        var query = ParseQuery(uri.Query);

        if (IsLikelyMediaHost(host))
        {
            score -= 140;
        }

        if (IsLikelyMediaPath(path))
        {
            score -= 120;
        }

        if (IsAmazonHost(host))
        {
            score += 70;
            if (path.Contains("/dp/", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("/gp/product/", StringComparison.OrdinalIgnoreCase))
            {
                score += 45;
            }
            if (query.TryGetValue("tag", out var tag) && !string.IsNullOrWhiteSpace(tag))
            {
                score += 20;
            }
        }

        if (IsMercadoLivreHost(host))
        {
            score += 70;
            if (IsMercadoLivreProductUri(uri))
            {
                score += 50;
            }
            if (IsMercadoLivreSocialOrShortUri(uri))
            {
                score += 15;
            }
            if (query.TryGetValue("matt_tool", out var tool) && !string.IsNullOrWhiteSpace(tool) &&
                query.TryGetValue("matt_word", out var word) && !string.IsNullOrWhiteSpace(word))
            {
                score += 20;
            }
            // Short link hosts (meli.la, meli.co) are inputs that need expansion,
            // NOT final affiliate URLs. Penalize heavily to prevent early return.
            if (host.Equals("meli.la", StringComparison.OrdinalIgnoreCase) ||
                host.Equals("meli.co", StringComparison.OrdinalIgnoreCase))
            {
                score -= 100;
            }
        }

        if (IsShopeeHost(host))
        {
            score += 65;
        }

        if (host.Contains("shein.com", StringComparison.OrdinalIgnoreCase))
        {
            score += 65;
            if (query.TryGetValue("url_from", out var shein) && !string.IsNullOrWhiteSpace(shein))
            {
                score += 20;
            }
        }

        if (IsShortLink(url))
        {
            score += 10;
        }

        return score;
    }

    private static bool IsLikelyMediaHost(string host)
    {
        return host.Contains("images-amazon.com", StringComparison.OrdinalIgnoreCase)
               || host.Contains("ssl-images-amazon.com", StringComparison.OrdinalIgnoreCase)
               || host.Contains("media-amazon.com", StringComparison.OrdinalIgnoreCase)
               || host.Contains("mmg.whatsapp.net", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLikelyMediaPath(string path)
        => Regex.IsMatch(path ?? string.Empty, @"\.(jpg|jpeg|png|gif|webp|bmp|svg|avif|mp4|webm|m3u8|pdf)$", RegexOptions.IgnoreCase);

    private static bool IsMercadoLivreSocialOrShortUri(Uri uri)
    {
        var host = NormalizeHost(uri.Host);
        if (host.Equals("meli.la", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("meli.co", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IsMercadoLivreSocial(uri.ToString());
    }

    private static bool TryExtractGoUrl(Uri uri, out Uri? goUri)
    {
        goUri = null;
        var raw = uri.ToString().Replace("&amp;", "&", StringComparison.OrdinalIgnoreCase);
        if (raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
        {
            raw = raw["file://".Length..];
        }
        if (!raw.Contains("/gz/webdevice/config", StringComparison.OrdinalIgnoreCase) &&
            !raw.Contains("/gz/account-verification", StringComparison.OrdinalIgnoreCase))
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
        if (string.IsNullOrWhiteSpace(mlbId)) return MercadoLivreItemValidation.Invalid;
        
        var normalizedId = mlbId.ToUpperInvariant();
        if (!normalizedId.StartsWith("MLB")) normalizedId = "MLB" + normalizedId;

        var token = await _mercadoLivreOAuthService.GetAccessTokenAsync(cancellationToken);
        
        // Try items API
        var status = await QueryMercadoLivreItemStatusAsync($"https://api.mercadolibre.com/items/{normalizedId}", token, cancellationToken);
        
        // If not found as item, try as product (Catalog)
        if (status == HttpStatusCode.NotFound)
        {
            status = await QueryMercadoLivreItemStatusAsync($"https://api.mercadolibre.com/products/{normalizedId}", token, cancellationToken);
        }

        if ((status == HttpStatusCode.Unauthorized || status == HttpStatusCode.Forbidden) && !string.IsNullOrWhiteSpace(token))
        {
            status = await QueryMercadoLivreItemStatusAsync($"https://api.mercadolibre.com/items/{normalizedId}", null, cancellationToken);
            if (status == HttpStatusCode.NotFound)
            {
                status = await QueryMercadoLivreItemStatusAsync($"https://api.mercadolibre.com/products/{normalizedId}", null, cancellationToken);
            }
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

    private async Task<HttpStatusCode> QueryMercadoLivreItemStatusAsync(string apiUrl, string? accessToken, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var req = new HttpRequestMessage(HttpMethod.Get, apiUrl);
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            }

            using var res = await client.SendAsync(req, cancellationToken);
            return res.StatusCode;
        }
        catch
        {
            return HttpStatusCode.InternalServerError;
        }
    }

    private async Task<string?> ResolveMercadoLivreCanonicalUrlAsync(string mlbId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(mlbId))
        {
            return null;
        }

        var normalizedId = mlbId.ToUpperInvariant();
        if (!normalizedId.StartsWith("MLB", StringComparison.OrdinalIgnoreCase))
        {
            normalizedId = "MLB" + normalizedId;
        }

        var token = await _mercadoLivreOAuthService.GetAccessTokenAsync(cancellationToken);

        var permalink = await QueryMercadoLivrePermalinkAsync($"https://api.mercadolibre.com/items/{normalizedId}", token, cancellationToken);
        if (string.IsNullOrWhiteSpace(permalink))
        {
            permalink = await QueryMercadoLivrePermalinkAsync($"https://api.mercadolibre.com/products/{normalizedId}", token, cancellationToken);
        }

        if (string.IsNullOrWhiteSpace(permalink) && !string.IsNullOrWhiteSpace(token))
        {
            permalink = await QueryMercadoLivrePermalinkAsync($"https://api.mercadolibre.com/items/{normalizedId}", null, cancellationToken);
            if (string.IsNullOrWhiteSpace(permalink))
            {
                permalink = await QueryMercadoLivrePermalinkAsync($"https://api.mercadolibre.com/products/{normalizedId}", null, cancellationToken);
            }
        }

        return permalink;
    }

    private async Task<string?> QueryMercadoLivrePermalinkAsync(string apiUrl, string? accessToken, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var req = new HttpRequestMessage(HttpMethod.Get, apiUrl);
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            }

            using var res = await client.SendAsync(req, cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                return null;
            }

            var payload = await res.Content.ReadAsStringAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(payload))
            {
                return null;
            }

            using var doc = JsonDocument.Parse(payload);
            if (doc.RootElement.TryGetProperty("permalink", out var permalinkProp))
            {
                var permalink = permalinkProp.GetString();
                if (Uri.TryCreate(permalink, UriKind.Absolute, out _))
                {
                    return permalink;
                }
            }

            if (doc.RootElement.TryGetProperty("canonical", out var canonicalProp))
            {
                var canonical = canonicalProp.GetString();
                if (Uri.TryCreate(canonical, UriKind.Absolute, out _))
                {
                    return canonical;
                }
            }

            return null;
        }
        catch
        {
            return null;
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

    private async Task<(bool Success, string? Url, bool CorrectionApplied, string? Note, string? Error)> ConvertAmazonWithCreatorApiAsync(
        Uri resolved,
        string partnerTag,
        CancellationToken cancellationToken)
    {
        var asin = ExtractAmazonAsin(resolved);
        if (string.IsNullOrWhiteSpace(asin))
        {
            return (false, null, false, "ASIN nao encontrado na URL Amazon.", "ASIN nao encontrado");
        }

        var item = await _amazonCreatorApiClient.GetItemAsync(asin, partnerTag, cancellationToken);
        if (item is null || string.IsNullOrWhiteSpace(item.DetailPageUrl))
        {
            return (false, null, false, $"Creator API nao retornou link para ASIN {asin}.", "Creator API sem link de detalhe");
        }

        return (true, item.DetailPageUrl.Trim(), true, $"Link oficial via Creator API (ASIN {asin}).", null);
    }

    private async Task<(bool Success, string? Url, bool CorrectionApplied, string? Note, string? Error)> ConvertAmazonWithOfficialApiAsync(
        Uri resolved,
        CancellationToken cancellationToken)
    {
        var asin = ExtractAmazonAsin(resolved);
        if (string.IsNullOrWhiteSpace(asin))
        {
            return (false, null, false, "ASIN nao encontrado na URL Amazon.", "ASIN nao encontrado");
        }

        var item = await _amazonPaApiClient.GetItemAsync(asin, cancellationToken);
        if (item is null || string.IsNullOrWhiteSpace(item.DetailPageUrl))
        {
            return (false, null, false, $"PA-API nao retornou link para ASIN {asin}.", "PA-API sem link de detalhe");
        }

        return (true, item.DetailPageUrl.Trim(), true, $"Link oficial via PA-API (ASIN {asin}).", null);
    }

    private static string? ExtractAmazonAsin(Uri uri)
    {
        var path = (uri.AbsolutePath ?? string.Empty).ToUpperInvariant();
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var patterns = new[]
        {
            @"/DP/(?<asin>[A-Z0-9]{10})(?:[/?]|$)",
            @"/GP/PRODUCT/(?<asin>[A-Z0-9]{10})(?:[/?]|$)",
            @"/GP/AW/D/(?<asin>[A-Z0-9]{10})(?:[/?]|$)",
            @"/PRODUCT/(?<asin>[A-Z0-9]{10})(?:[/?]|$)"
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(path, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success)
            {
                return match.Groups["asin"].Value;
            }
        }

        var query = uri.Query ?? string.Empty;
        var queryMatch = Regex.Match(query, @"(?:^|[?&])asin=(?<asin>[A-Za-z0-9]{10})(?:&|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return queryMatch.Success ? queryMatch.Groups["asin"].Value.ToUpperInvariant() : null;
    }

    private string ResolveAmazonPartnerTag()
    {
        var configured = _options.AmazonProductApi?.PartnerTag;
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim();
        }

        return (_options.AmazonTag ?? string.Empty).Trim();
    }

    private static bool IsAmazonPartnerTagValid(string? partnerTag)
    {
        if (string.IsNullOrWhiteSpace(partnerTag))
        {
            return false;
        }

        var normalized = partnerTag.Trim();
        if (string.Equals(normalized, "CHANGE_ME_AMAZON_TAG", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // PartnerTag comum termina com sufixo de marketplace (ex.: -20 no BR).
        return Regex.IsMatch(normalized, @"^[A-Za-z0-9][A-Za-z0-9-]{2,}$", RegexOptions.CultureInvariant)
               && normalized.Contains('-', StringComparison.Ordinal);
    }

    private async Task<(bool IsAffiliated, string? Error)> ValidateAffiliateAsync(string store, string url, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return (false, "URL convertida inválida");
        }

        var query = ParseQuery(uri.Query);
        var amazonExpectedTag = ResolveAmazonPartnerTag();
        (bool IsAffiliated, string? Error) result = store switch
        {
            "Amazon" => IsAmazonPartnerTagValid(amazonExpectedTag)
                        && query.TryGetValue("tag", out var tag)
                        && string.Equals(tag, amazonExpectedTag, StringComparison.OrdinalIgnoreCase)
                ? (true, null)
                : (false, IsAmazonPartnerTagValid(amazonExpectedTag)
                    ? $"Tag Amazon inválida (esperado: {amazonExpectedTag})"
                    : "PartnerTag Amazon nao configurada"),
            "Mercado Livre" => (IsMercadoLivreProductUri(uri) || IsMercadoLivreSocialOrShortUri(uri))
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

    private string ApplyTrackingTags(string url, string store, string? source)
    {
        var cfg = _options.LinkTagging;
        if (!cfg.Enabled || string.IsNullOrWhiteSpace(url))
        {
            return url;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return url;
        }

        var entryPoint = ResolveTrackingEntryPoint(source);
        var query = ParseQuery(uri.Query);
        UpsertTrackingParam(query, "utm_source", cfg.Source, cfg.OverwriteExisting);
        UpsertTrackingParam(query, "utm_medium", cfg.Medium, cfg.OverwriteExisting);

        var campaign = cfg.Campaign?.Trim() ?? string.Empty;
        if (cfg.IncludeStoreInCampaign && !string.IsNullOrWhiteSpace(store))
        {
            var safeStore = Regex.Replace(store.Trim().ToLowerInvariant(), @"[^a-z0-9]+", "_");
            safeStore = Regex.Replace(safeStore, @"_+", "_").Trim('_');
            if (!string.IsNullOrWhiteSpace(safeStore))
            {
                campaign = string.IsNullOrWhiteSpace(campaign) ? safeStore : $"{campaign}_{safeStore}";
            }
        }

        UpsertTrackingParam(query, "utm_campaign", campaign, cfg.OverwriteExisting);
        UpsertTrackingParam(query, "utm_term", cfg.Term, cfg.OverwriteExisting);
        var content = BuildContentTag(cfg.Content, entryPoint);
        UpsertTrackingParam(query, "utm_content", content, cfg.OverwriteExisting);
        UpsertTrackingParam(query, "ab_entry", entryPoint, cfg.OverwriteExisting);

        if (cfg.ExtraParams is not null)
        {
            foreach (var pair in cfg.ExtraParams)
            {
                UpsertTrackingParam(query, pair.Key, pair.Value, cfg.OverwriteExisting);
            }
        }

        var encodedQuery = string.Join("&", query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var ub = new UriBuilder(uri)
        {
            Query = encodedQuery
        };
        return ub.Uri.ToString();
    }

    private static void UpsertTrackingParam(Dictionary<string, string> query, string key, string? value, bool overwrite)
    {
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (!overwrite && query.TryGetValue(key, out var existing) && !string.IsNullOrWhiteSpace(existing))
        {
            return;
        }

        query[key] = value.Trim();
    }

    private static string BuildContentTag(string? baseContent, string entryPoint)
    {
        var trimmed = (baseContent ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return entryPoint;
        }

        return $"{trimmed}_{entryPoint}";
    }

    private static string ResolveTrackingEntryPoint(string? source)
    {
        var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return "conversor_web";
        }

        if (normalized.Contains("whatsapp", StringComparison.Ordinal))
        {
            return "whatsapp";
        }

        if (normalized.Contains("telegram", StringComparison.Ordinal))
        {
            return "telegram";
        }

        if (normalized.Contains("instagram", StringComparison.Ordinal))
        {
            return "instagram_ofertas";
        }

        if (normalized.Contains("catalog", StringComparison.Ordinal))
        {
            return "catalogo_site";
        }

        if (normalized.Contains("conversor", StringComparison.Ordinal) || normalized.Contains("web", StringComparison.Ordinal))
        {
            return "conversor_web";
        }

        return "conversor_web";
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
