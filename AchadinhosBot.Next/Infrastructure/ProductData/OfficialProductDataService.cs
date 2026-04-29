using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Amazon;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using AchadinhosBot.Next.Infrastructure.MercadoLivre;

namespace AchadinhosBot.Next.Infrastructure.ProductData;

public sealed class OfficialProductDataService
{
    private static readonly TimeSpan ResolvedUrlCacheTtl = TimeSpan.FromMinutes(20);
    private static readonly TimeSpan MercadoLivreItemIdCacheTtl = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan MercadoLivreSearchCacheTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MercadoLivreScrapeMergeWait = TimeSpan.FromMilliseconds(800);
    private readonly AmazonPaApiClient _amazonPaApiClient;
    private readonly AmazonCreatorApiClient _amazonCreatorApiClient;
    private readonly AmazonHtmlScraperService _amazonHtmlScraper;
    private readonly AmazonPlaywrightScraperClient _amazonPlaywrightScraper;
    private readonly MercadoLivreHtmlScraperService _mercadoLivreHtmlScraper;
    private readonly IMercadoLivreOAuthService _mercadoLivreOAuthService;
    private readonly AffiliateOptions _affiliateOptions;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OfficialProductDataService> _logger;
    private readonly IMemoryCache _memoryCache;

    public OfficialProductDataService(
        AmazonPaApiClient amazonPaApiClient,
        AmazonCreatorApiClient amazonCreatorApiClient,
        AmazonHtmlScraperService amazonHtmlScraper,
        AmazonPlaywrightScraperClient amazonPlaywrightScraper,
        MercadoLivreHtmlScraperService mercadoLivreHtmlScraper,
        IMercadoLivreOAuthService mercadoLivreOAuthService,
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        IMemoryCache memoryCache,
        ILogger<OfficialProductDataService> logger)
    {
        _amazonPaApiClient = amazonPaApiClient;
        _amazonCreatorApiClient = amazonCreatorApiClient;
        _amazonHtmlScraper = amazonHtmlScraper;
        _amazonPlaywrightScraper = amazonPlaywrightScraper;
        _mercadoLivreHtmlScraper = mercadoLivreHtmlScraper;
        _mercadoLivreOAuthService = mercadoLivreOAuthService;
        _affiliateOptions = affiliateOptions.Value;
        _httpClientFactory = httpClientFactory;
        _memoryCache = memoryCache;
        _logger = logger;

        if (_affiliateOptions.ShopeeProductApi.Enabled &&
            (string.IsNullOrWhiteSpace(_affiliateOptions.ShopeeAppId) || string.IsNullOrWhiteSpace(_affiliateOptions.ShopeeSecret)))
        {
            _logger.LogWarning("ShopeeProductApi habilitada sem credenciais completas. O runtime vai cair para fallbacks quando necessario.");
        }
    }

    public async Task<OfficialProductDataResult?> TryGetBestAsync(string originalUrl, string? convertedUrl, CancellationToken ct)
    {
        var cacheKey = $"official-product:{originalUrl?.Trim()}|{convertedUrl?.Trim()}";
        if (_memoryCache.TryGetValue(cacheKey, out OfficialProductDataResult? cachedResult))
        {
            return cachedResult;
        }

        var logs = new List<string>();
        logs.Add($"Iniciando conversão: {originalUrl}");
        var consultedStores = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        var urlCandidates = new List<string>();
        AddCandidate(urlCandidates, convertedUrl);
        AddCandidate(urlCandidates, originalUrl);

        var results = new List<OfficialProductDataResult>();
        var resolvedCandidates = new List<string>(urlCandidates);
        foreach (var rawUrl in urlCandidates.ToList())
        {
            var resolved = await TryResolveFinalUrlAsync(rawUrl, ct);
            if (!string.IsNullOrWhiteSpace(resolved))
            {
                logs.Add($"URL resolvida: {resolved}");
                AddCandidate(resolvedCandidates, resolved);
            }
        }

        foreach (var candidate in resolvedCandidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var displayHost = Uri.TryCreate(candidate, UriKind.Absolute, out var cUri) ? cUri.Host : "URL inválida";
            var storeLabel = Uri.TryCreate(candidate, UriKind.Absolute, out var hostUri)
                ? GetStoreLabel(hostUri.Host)
                : "Link";
            if (!string.Equals(storeLabel, "Link", StringComparison.OrdinalIgnoreCase))
            {
                consultedStores.Add(storeLabel);
            }
            logs.Add($"Extraindo dados de: {displayHost}");
            var result = await TryGetFromSingleUrlAsync(candidate, ct);
            if (result is not null)
            {
                consultedStores.Add(result.Store);
                logs.Add($"Produto encontrado na {result.Store}: {result.Title} ({result.CurrentPrice})");
                results.Add(result);
            }
        }

        // --- NEW: CROSS-STORE SEARCH ---
        if (results.Count > 0)
        {
            var storesRepresented = results.Select(r => r.Store).Distinct().ToList();
            var bestInitial = results.OrderByDescending(Score).First();
            var titleToSearch = bestInitial.Title;

            if (!string.IsNullOrWhiteSpace(titleToSearch) && titleToSearch.Length > 10)
            {
                logs.Add($"Iniciando busca cross-store para: {titleToSearch}");
                var queryVariants = BuildSearchQueries(titleToSearch);
                logs.Add($"Queries geradas para comparação: {string.Join(" | ", queryVariants)}");

                if (!storesRepresented.Contains("Amazon"))
                {
                    consultedStores.Add("Amazon");
                    logs.Add("Pesquisando na Amazon...");
                    var amazonResult = await SearchSingleStoreWithFallbackAsync(queryVariants, SearchAmazonAsync, "Amazon", logs, ct);
                    if (amazonResult is not null)
                    {
                        logs.Add($"Oferta alternativa encontrada na Amazon: {amazonResult.CurrentPrice}");
                        results.Add(amazonResult);
                    }
                }

                if (!storesRepresented.Contains("Shopee"))
                {
                    consultedStores.Add("Shopee");
                    logs.Add("Pesquisando na Shopee...");
                    var shopeeResult = await SearchSingleStoreWithFallbackAsync(queryVariants, SearchShopeeAsync, "Shopee", logs, ct);
                    if (shopeeResult is not null)
                    {
                        logs.Add($"Oferta alternativa encontrada na Shopee: {shopeeResult.CurrentPrice}");
                        results.Add(shopeeResult);
                    }
                }

                if (!storesRepresented.Contains("Mercado Livre"))
                {
                    consultedStores.Add("Mercado Livre");
                    logs.Add("Pesquisando no Mercado Livre...");
                    var mlResults = await SearchMercadoLivreWithFallbackAsync(queryVariants, logs, ct);
                    foreach (var sr in mlResults)
                    {
                        logs.Add($"Oferta alternativa encontrada no Mercado Livre: {sr.CurrentPrice}");
                        results.Add(sr);
                    }
                }

                results = results
                    .GroupBy(r => $"{r.Store}|{r.SourceUrl}|{r.CurrentPrice}", StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .ToList();
            }
        }

        if (results.Count == 0)
        {
            foreach (var candidate in resolvedCandidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var fallback = await TryGetLinkMetaFallbackAsync(candidate, ct);
                if (fallback is null)
                {
                    continue;
                }

                logs.Add($"Fallback de metadados do link aplicado: {fallback.Store} ({fallback.DataSource})");
                results.Add(fallback);
            }

            if (results.Count == 0)
            {
                logs.Add("Nenhum produto identificado em nenhuma loja.");
                _memoryCache.Set<OfficialProductDataResult?>(cacheKey, null, TimeSpan.FromMinutes(5));
                return null;
            }
        }

        var best = results
            .OrderByDescending(Score)
            .First();

        logs.Add($"Melhor oferta selecionada: {best.Store} por {best.CurrentPrice}");
        if (!string.IsNullOrWhiteSpace(best.CouponCode))
        {
            logs.Add($"Cupom identificado: {best.CouponCode} ({best.CouponDescription})");
        }

        var comparisons = results
            .Where(r => r != best)
            .Select(r => new PriceComparisonResult(
                r.Store, 
                r.Title ?? "Produto", 
                r.CurrentPrice ?? "Indisponivel", 
                r.SourceUrl,
                r.CouponCode))
            .ToList();

        // --- NEW: SAVINGS CALCULATION (PRICE PROOF) ---
        string? savingsDisplay = null;
        int? savingsPercent = null;
        if (comparisons.Count > 0)
        {
            var bestPrice = ParsePriceNumber(best.CurrentPrice);
            var others = comparisons
                .Select(c => ParsePriceNumber(c.Price))
                .Where(p => p.HasValue)
                .Select(p => p!.Value)
                .ToList();

            if (bestPrice.HasValue && others.Count > 0)
            {
                var maxOther = others.Max();
                if (maxOther > bestPrice.Value)
                {
                    var diff = maxOther - bestPrice.Value;
                    savingsDisplay = $"Economia de R$ {diff:N2}";
                    savingsPercent = (int)Math.Round((diff / maxOther) * 100);
                    logs.Add($"Economia VIP detectada: {savingsDisplay} ({savingsPercent}% abaixo do maior preço)");
                }
            }
        }

        var finalResult = best with 
        { 
            SearchResults = comparisons, 
            ProcessingLogs = logs,
            SavingsDisplay = savingsDisplay,
            SavingsPercent = savingsPercent,
            StoresConsulted = consultedStores.OrderBy(x => x).ToList(),
            MatchesFound = comparisons.Count
        };

        _memoryCache.Set(cacheKey, finalResult, TimeSpan.FromMinutes(15));
        return finalResult;
    }

    private async Task<OfficialProductDataResult?> TryGetFromSingleUrlAsync(string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var host = uri.Host.ToLowerInvariant();
        if (IsAmazonHost(host))
        {
            return await TryGetAmazonDataAsync(uri, ct);
        }

        if (IsMercadoLivreHost(host))
        {
            return await TryGetMercadoLivreDataAsync(uri, ct);
        }

        if (IsShopeeHost(host))
        {
            return await TryGetShopeeDataAsync(uri, ct);
        }

        return null;
    }

    private async Task<OfficialProductDataResult?> TryGetAmazonDataAsync(Uri uri, CancellationToken ct)
    {
        var asin = ExtractAmazonAsin(uri);
        var resolvedAmazonUrl = await TryResolveFinalUrlAsync(uri.ToString(), ct);
        if (string.IsNullOrWhiteSpace(asin) && !string.IsNullOrWhiteSpace(resolvedAmazonUrl) &&
            Uri.TryCreate(resolvedAmazonUrl, UriKind.Absolute, out var resolvedAmazonUri))
        {
            asin = ExtractAmazonAsin(resolvedAmazonUri);
            uri = resolvedAmazonUri;
        }
        if (string.IsNullOrWhiteSpace(asin))
        {
            return null;
        }

        // Tentar PA-API primeiro
        if (_amazonPaApiClient.IsConfigured)
        {
            var item = await _amazonPaApiClient.GetItemAsync(asin, ct);
            if (item is not null)
            {
                var current = NormalizePriceDisplay(item.PriceDisplay);
                var previous = ExtractPreviousPrice(item.PriceDisplay);
                var discount = ComputeDiscount(previous, current);

                return new OfficialProductDataResult(
                    Store: "Amazon",
                    Title: item.Title,
                    CurrentPrice: current,
                    PreviousPrice: previous,
                    DiscountPercent: discount,
                    Images: item.Images ?? new List<string>(),
                    IsOfficial: true,
                    DataSource: "amazon_paapi",
                    SourceUrl: uri.ToString(),
                    EstimatedDelivery: null,
                    VideoUrl: null);
            }
        }

        // Fallback: Creator API
        if (_amazonCreatorApiClient.IsConfigured)
        {
            var partnerTag = _affiliateOptions.AmazonTag;
            var creatorItem = await _amazonCreatorApiClient.GetItemAsync(asin, partnerTag, ct);
            if (creatorItem is not null)
            {
                var current = NormalizePriceDisplay(creatorItem.PriceDisplay);
                var previous = ExtractPreviousPrice(creatorItem.PriceDisplay);
                var discount = ComputeDiscount(previous, current);

                return new OfficialProductDataResult(
                    Store: "Amazon",
                    Title: creatorItem.Title,
                    CurrentPrice: current,
                    PreviousPrice: previous,
                    DiscountPercent: discount,
                    Images: creatorItem.Images ?? new List<string>(),
                    IsOfficial: true,
                    DataSource: "amazon_creator_api",
                    SourceUrl: uri.ToString(),
                    EstimatedDelivery: null,
                    VideoUrl: null);
            }
        }

        // Fallback: Playwright scraper (real browser, bypasses CAPTCHA)
        if (_amazonPlaywrightScraper is not null)
        {
            var pw = await _amazonPlaywrightScraper.ScrapeAsync(asin, ct);
            if (pw is not null && (!string.IsNullOrWhiteSpace(pw.Title) || pw.Images.Count > 0))
            {
                return new OfficialProductDataResult(
                    Store: "Amazon",
                    Title: pw.Title,
                    CurrentPrice: pw.Price,
                    PreviousPrice: pw.OldPrice,
                    DiscountPercent: pw.DiscountPercent,
                    Images: pw.Images,
                    IsOfficial: false,
                    DataSource: "amazon_playwright",
                    SourceUrl: uri.ToString(),
                    EstimatedDelivery: null,
                    VideoUrl: null,
                    IsLightningDeal: pw.IsLightningDeal,
                    LightningDealExpiry: pw.LightningDealExpiry,
                    CouponCode: pw.CouponCode,
                    CouponDescription: pw.CouponDescription);
            }
        }

        // Fallback: try the fully resolved product URL first, then the canonical ASIN templates.
        {
            AmazonScrapedProduct? scraped = null;
            if (!string.IsNullOrWhiteSpace(resolvedAmazonUrl))
            {
                scraped = await _amazonHtmlScraper.ScrapeUrlAsync(resolvedAmazonUrl, ct);
            }
            scraped ??= await _amazonHtmlScraper.ScrapeAsync(asin, ct);
            if (scraped is not null && (!string.IsNullOrWhiteSpace(scraped.Title) || scraped.Images.Count > 0))
            {
                return new OfficialProductDataResult(
                    Store: "Amazon",
                    Title: scraped.Title,
                    CurrentPrice: scraped.Price,
                    PreviousPrice: scraped.OldPrice,
                    DiscountPercent: scraped.DiscountPercent,
                    Images: scraped.Images,
                    IsOfficial: false,
                    DataSource: "amazon_html_scraper",
                    SourceUrl: uri.ToString(),
                    EstimatedDelivery: null,
                    VideoUrl: null,
                    IsLightningDeal: scraped.IsLightningDeal,
                    LightningDealExpiry: scraped.LightningDealExpiry,
                    CouponCode: scraped.CouponCode,
                    CouponDescription: scraped.CouponDescription);
            }
        }

        return null;
    }

    private async Task<OfficialProductDataResult?> TryGetMercadoLivreDataAsync(Uri uri, CancellationToken ct)
    {
        var resolvedUrl = await TryResolveFinalUrlAsync(uri.ToString(), ct) ?? uri.ToString();
        var scrapedTask = _mercadoLivreHtmlScraper.ScrapeUrlAsync(resolvedUrl, ct);

        var itemId = await TryResolveMercadoLivreItemIdAsync(uri, ct);
        if (string.IsNullOrWhiteSpace(itemId))
        {
            var scrapedFallback = await scrapedTask;
            if (scrapedFallback != null && (!string.IsNullOrWhiteSpace(scrapedFallback.Title) || scrapedFallback.Images.Count > 0))
            {
                return new OfficialProductDataResult(
                    Store: "Mercado Livre",
                    Title: scrapedFallback.Title,
                    CurrentPrice: scrapedFallback.Price,
                    PreviousPrice: scrapedFallback.OldPrice,
                    DiscountPercent: scrapedFallback.DiscountPercent,
                    Images: scrapedFallback.Images,
                    IsOfficial: false,
                    DataSource: "mercadolivre_html_scraper",
                    SourceUrl: resolvedUrl,
                    EstimatedDelivery: scrapedFallback.Delivery,
                    VideoUrl: null,
                    IsLightningDeal: scrapedFallback.IsLightningDeal,
                    CouponCode: scrapedFallback.CouponCode,
                    CouponDescription: scrapedFallback.CouponDescription);
            }
            return null;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var endpoint = $"https://api.mercadolibre.com/items/{itemId}";
            var accessToken = await _mercadoLivreOAuthService.GetAccessTokenAsync(ct);
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }

            using var response = await client.SendAsync(request, ct);
            OfficialProductDataResult? apiResult = null;

            if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
            {
                using var fallbackResponse = await client.GetAsync(endpoint, ct);
                if (fallbackResponse.IsSuccessStatusCode)
                {
                    var fallbackBody = await fallbackResponse.Content.ReadAsStringAsync(ct);
                    using var fallbackDoc = JsonDocument.Parse(fallbackBody);
                    apiResult = ParseMercadoLivreItemResponse(uri, fallbackDoc);
                }
            }
            else if (response.IsSuccessStatusCode)
            {
                 var body = await response.Content.ReadAsStringAsync(ct);
                 using var doc = JsonDocument.Parse(body);
                 apiResult = ParseMercadoLivreItemResponse(uri, doc);
            }

            if (apiResult is not null)
            {
                var scrapeCompletedQuickly = await Task.WhenAny(scrapedTask, Task.Delay(MercadoLivreScrapeMergeWait, ct)) == scrapedTask;
                if (!scrapeCompletedQuickly)
                {
                    return apiResult;
                }

                var scraped = await scrapedTask;
                if (scraped != null)
                {
                    return apiResult with
                    {
                        EstimatedDelivery = apiResult.EstimatedDelivery ?? scraped.Delivery,
                        Title = apiResult.Title ?? scraped.Title,
                        DataSource = "mercadolivre_api_and_scraper",
                        PreviousPrice = scraped.IsLightningDeal ? scraped.OldPrice : apiResult.PreviousPrice,
                        CurrentPrice = scraped.IsLightningDeal ? scraped.Price : apiResult.CurrentPrice,
                        DiscountPercent = scraped.IsLightningDeal ? scraped.DiscountPercent : apiResult.DiscountPercent,
                        IsLightningDeal = scraped.IsLightningDeal,
                        CouponCode = scraped.CouponCode,
                        CouponDescription = scraped.CouponDescription
                    };
                }

                return apiResult;
            }

            var scrapedFallback = await scrapedTask;

            if (scrapedFallback != null && (!string.IsNullOrWhiteSpace(scrapedFallback.Title) || scrapedFallback.Images.Count > 0))
            {
                return new OfficialProductDataResult(
                    Store: "Mercado Livre",
                    Title: scrapedFallback.Title,
                    CurrentPrice: scrapedFallback.Price,
                    PreviousPrice: scrapedFallback.OldPrice,
                    DiscountPercent: scrapedFallback.DiscountPercent,
                    Images: scrapedFallback.Images,
                    IsOfficial: false,
                    DataSource: "mercadolivre_html_scraper",
                    SourceUrl: resolvedUrl,
                    EstimatedDelivery: scrapedFallback.Delivery,
                    VideoUrl: null,
                    IsLightningDeal: scrapedFallback.IsLightningDeal,
                    CouponCode: scrapedFallback.CouponCode,
                    CouponDescription: scrapedFallback.CouponDescription);
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao obter dados oficiais do Mercado Livre.");
            return null;
        }
    }

    private async Task<string?> TryResolveMercadoLivreItemIdAsync(Uri uri, CancellationToken ct)
    {
        var cacheKey = $"ml-item-id:{uri}";
        if (_memoryCache.TryGetValue(cacheKey, out string? cachedItemId))
        {
            return cachedItemId;
        }

        var itemId = ExtractMercadoLivreItemId(uri);
        if (!string.IsNullOrWhiteSpace(itemId))
        {
            _memoryCache.Set(cacheKey, itemId, MercadoLivreItemIdCacheTtl);
            return itemId;
        }

        var resolved = await TryResolveFinalUrlAsync(uri.ToString(), ct);
        if (!string.IsNullOrWhiteSpace(resolved) &&
            Uri.TryCreate(resolved, UriKind.Absolute, out var resolvedUri))
        {
            itemId = ExtractMercadoLivreItemId(resolvedUri);
            if (!string.IsNullOrWhiteSpace(itemId))
            {
                _memoryCache.Set(cacheKey, itemId, MercadoLivreItemIdCacheTtl);
                return itemId;
            }
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var html = await client.GetStringAsync(resolved ?? uri.ToString(), ct);
            var fromHtml = ExtractMercadoLivreItemIdFromText(html);
            if (!string.IsNullOrWhiteSpace(fromHtml))
            {
                _memoryCache.Set(cacheKey, fromHtml, MercadoLivreItemIdCacheTtl);
                return fromHtml;
            }
        }
        catch
        {
        }

        _memoryCache.Set<string?>(cacheKey, null, TimeSpan.FromMinutes(5));
        return null;
    }

    private static OfficialProductDataResult? ParseMercadoLivreItemResponse(Uri uri, JsonDocument doc)
    {
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var title = TryGetString(root, "title");
        var currency = TryGetString(root, "currency_id");
        var price = TryGetDecimal(root, "price");
        var originalPrice = TryGetDecimal(root, "original_price");
        var pictures = new List<string>();
        if (root.TryGetProperty("pictures", out var picturesNode) && picturesNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in picturesNode.EnumerateArray().Take(10))
            {
                var url = TryGetString(item, "secure_url") ?? TryGetString(item, "url");
                if (!string.IsNullOrWhiteSpace(url))
                {
                    pictures.Add(url.Trim());
                }
            }
        }

        // Extract shipping / delivery info
        string? estimatedDelivery = null;
        if (root.TryGetProperty("shipping", out var shippingNode) && shippingNode.ValueKind == JsonValueKind.Object)
        {
            var freeShipping = shippingNode.TryGetProperty("free_shipping", out var fsNode) && fsNode.ValueKind == JsonValueKind.True;
            var logisticType = TryGetString(shippingNode, "logistic_type") ?? string.Empty;
            var mode = TryGetString(shippingNode, "mode") ?? string.Empty;

            if (freeShipping)
            {
                estimatedDelivery = "Entrega grátis";
            }
            else if (!string.IsNullOrWhiteSpace(logisticType) || !string.IsNullOrWhiteSpace(mode))
            {
                estimatedDelivery = "Frete pago";
            }
        }
        // Also check top-level free_shipping fallback
        if (estimatedDelivery is null &&
            root.TryGetProperty("free_shipping", out var topFsNode) &&
            topFsNode.ValueKind == JsonValueKind.True)
        {
            estimatedDelivery = "Entrega grátis";
        }

        var current = FormatCurrency(price, currency);
        var previous = FormatCurrency(originalPrice, currency);
        var discount = ComputeDiscount(originalPrice, price);

        if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(current) && pictures.Count == 0)
        {
            return null;
        }

        return new OfficialProductDataResult(
            Store: "Mercado Livre",
            Title: title,
            CurrentPrice: current,
            PreviousPrice: previous,
            DiscountPercent: discount,
            Images: pictures,
            IsOfficial: true,
            DataSource: "mercadolivre_items_api",
            SourceUrl: uri.ToString(),
            EstimatedDelivery: estimatedDelivery,
            VideoUrl: null); // ML usually uses a separate video_id which is harder to fetch directly, keeping null for now
    }

    private async Task<OfficialProductDataResult?> TryGetShopeeDataAsync(Uri uri, CancellationToken ct)
    {
        var appId = _affiliateOptions.ShopeeAppId?.Trim();
        var secret = _affiliateOptions.ShopeeSecret?.Trim();
        var targetUrl = uri.ToString();
        if (targetUrl.Contains("s.shopee.com.br", StringComparison.OrdinalIgnoreCase) || 
            targetUrl.Contains("shope.ee", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var resolverClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
                resolverClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                var response = await resolverClient.GetAsync(uri, ct);
                var location = response.Headers.Location?.ToString();
                if (!string.IsNullOrEmpty(location))
                {
                    targetUrl = location;
                }
                else
                {
                    var html = await response.Content.ReadAsStringAsync(ct);
                    var matchUrl = Regex.Match(html, @"url=([^""]+)");
                    if (matchUrl.Success) targetUrl = matchUrl.Groups[1].Value;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Falha ao resolver shortlink da Shopee: {Url}", uri);
            }
        }

        long? shopId = null;
        long? itemId = null;
        var match = Regex.Match(targetUrl, @"-i[._](\d+)[._](\d+)");
        if (match.Success)
        {
            if (long.TryParse(match.Groups[1].Value, out var sId)) shopId = sId;
            if (long.TryParse(match.Groups[2].Value, out var mId)) itemId = mId;
        }
        else
        {
            match = Regex.Match(targetUrl, @"shopee\.com\.br/[^/]+/(\d+)/(\d+)");
            if (match.Success)
            {
                if (long.TryParse(match.Groups[1].Value, out var sId)) shopId = sId;
                if (long.TryParse(match.Groups[2].Value, out var mId)) itemId = mId;
            }
            else
            {
                match = Regex.Match(targetUrl, @"(?:itemid|product_id|itemId)=(\d+)");
                if (match.Success && long.TryParse(match.Groups[1].Value, out var mId)) itemId = mId;
            }
        }

        if (itemId is null || itemId <= 0)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(appId) && !string.IsNullOrWhiteSpace(secret))
        {
            var official = await TryGetShopeeGraphQlDataAsync(appId, secret, itemId.Value, targetUrl, ct);
            if (official is not null)
            {
                return official;
            }
        }

        if (shopId.HasValue && shopId.Value > 0)
        {
            var publicItem = await TryGetShopeePublicItemDataAsync(shopId.Value, itemId.Value, targetUrl, ct);
            if (publicItem is not null)
            {
                return publicItem;
            }
        }

        return null;
    }

    private async Task<OfficialProductDataResult?> TryGetShopeeGraphQlDataAsync(string appId, string secret, long itemId, string targetUrl, CancellationToken ct)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = $$"""{"query":"query {\n  productOfferV2(\n    itemId: {{itemId}}\n    page: 1\n    limit: 1\n    listType: 0\n  ) {\n    nodes {\n      itemId\n      productName\n      price\n      priceDiscountRate\n      imageUrl\n    }\n  }\n}"}""";
        var baseString = appId + timestamp + payload + secret;
        var sign = string.Empty;
        using (var sha256 = System.Security.Cryptography.SHA256.Create())
        {
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(baseString));
            sign = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        try
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "https://open-api.affiliate.shopee.com.br/graphql");
            request.Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
            request.Headers.Add("Authorization", $"SHA256 Credential={appId}, Timestamp={timestamp}, Signature={sign}");

            var client = _httpClientFactory.CreateClient("default");
            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            if (!doc.RootElement.TryGetProperty("data", out var dataNode) ||
                !dataNode.TryGetProperty("productOfferV2", out var offerNode) ||
                !offerNode.TryGetProperty("nodes", out var listNode) ||
                listNode.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var first = listNode.EnumerateArray().FirstOrDefault();
            if (first.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var title = TryGetString(first, "productName");
            var priceRawStr = TryGetString(first, "price");
            decimal.TryParse(priceRawStr, NumberStyles.Any, CultureInfo.InvariantCulture, out var priceRaw);
            var discount = TryGetIntPercent(first, "priceDiscountRate");
            var normalizedPrice = Math.Round(priceRaw, 2);
            var normalizedPrevious = discount.HasValue && discount.Value > 0 && discount.Value < 100
                ? Math.Round(normalizedPrice / (1m - discount.Value / 100m), 2)
                : normalizedPrice;

            var images = new List<string>();
            var imageUrl = TryGetString(first, "imageUrl");
            if (!string.IsNullOrWhiteSpace(imageUrl))
            {
                images.Add(imageUrl.Trim());
            }

            var current = FormatCurrency(normalizedPrice, "BRL");
            var previous = FormatCurrency(normalizedPrevious, "BRL");
            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(current) && images.Count == 0)
            {
                return null;
            }

            return new OfficialProductDataResult(
                Store: "Shopee",
                Title: title,
                CurrentPrice: current,
                PreviousPrice: previous,
                DiscountPercent: discount,
                Images: images.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                IsOfficial: true,
                DataSource: "shopee_affiliate_graphql",
                SourceUrl: targetUrl,
                EstimatedDelivery: null,
                VideoUrl: null);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao obter dados oficiais da Shopee via GraphQL.");
            return null;
        }
    }

    private async Task<OfficialProductDataResult?> TryGetShopeePublicItemDataAsync(long shopId, long itemId, string targetUrl, CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var response = await client.GetAsync($"https://shopee.com.br/api/v4/item/get?itemid={itemId}&shopid={shopId}", ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            if (!doc.RootElement.TryGetProperty("data", out var dataNode) || dataNode.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var itemNode = dataNode.TryGetProperty("item_basic", out var itemBasicNode) && itemBasicNode.ValueKind == JsonValueKind.Object
                ? itemBasicNode
                : dataNode;

            var title = TryGetString(itemNode, "name");
            var price = NormalizeShopeePrice(TryGetDecimal(itemNode, "price"));
            var previous = NormalizeShopeePrice(TryGetDecimal(itemNode, "price_before_discount"));
            var discount = ComputeDiscount(previous, price);

            var images = new List<string>();
            if (itemNode.TryGetProperty("images", out var imagesNode) && imagesNode.ValueKind == JsonValueKind.Array)
            {
                foreach (var imageNode in imagesNode.EnumerateArray().Take(10))
                {
                    var imageHash = imageNode.GetString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(imageHash))
                    {
                        images.Add(BuildShopeeImageUrl(imageHash));
                    }
                }
            }
            else
            {
                var imageHash = TryGetString(itemNode, "image");
                if (!string.IsNullOrWhiteSpace(imageHash))
                {
                    images.Add(BuildShopeeImageUrl(imageHash));
                }
            }

            string? videoUrl = null;
            if (itemNode.TryGetProperty("video_info_list", out var videoListNode) && videoListNode.ValueKind == JsonValueKind.Array)
            {
                foreach (var videoNode in videoListNode.EnumerateArray())
                {
                    videoUrl = TryGetString(videoNode, "video_url") ?? TryGetString(videoNode, "videoUrl");
                    if (!string.IsNullOrWhiteSpace(videoUrl))
                    {
                        break;
                    }
                }
            }

            var current = FormatCurrency(price, "BRL");
            var previousDisplay = FormatCurrency(previous, "BRL");
            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(current) && images.Count == 0 && string.IsNullOrWhiteSpace(videoUrl))
            {
                return null;
            }

            return new OfficialProductDataResult(
                Store: "Shopee",
                Title: title,
                CurrentPrice: current,
                PreviousPrice: previousDisplay,
                DiscountPercent: discount,
                Images: images.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                IsOfficial: false,
                DataSource: "shopee_public_item_api",
                SourceUrl: targetUrl,
                EstimatedDelivery: null,
                VideoUrl: videoUrl);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao obter dados publicos da Shopee: {ShopId}/{ItemId}", shopId, itemId);
            return null;
        }
    }

    private async Task<OfficialProductDataResult?> SearchAmazonAsync(string title, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(title)) return null;

        try
        {
            var searchTitle = title;
            // Clean title: take first 6-8 words for more accurate search
            var words = title.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (words.Length > 8) searchTitle = string.Join(" ", words.Take(8));

            var client = _httpClientFactory.CreateClient("default");
            var query = Uri.EscapeDataString(searchTitle);
            var searchUrl = $"https://www.amazon.com.br/s?k={query}";

            using var request = new HttpRequestMessage(HttpMethod.Get, searchUrl);
            request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36");
            
            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) return null;

            var html = await response.Content.ReadAsStringAsync(ct);
            // Look for ASINs in data-asin attributes
            var asinMatches = Regex.Matches(html, @"data-asin=""(?<asin>[A-Z0-9]{10})""", RegexOptions.IgnoreCase);
            
            var asins = asinMatches.Cast<Match>()
                .Select(m => m.Groups["asin"].Value)
                .Where(a => !string.IsNullOrEmpty(a))
                .Distinct()
                .Take(2) // Just try the first two relevant results
                .ToList();

            foreach (var asin in asins)
            {
                if (Uri.TryCreate($"https://www.amazon.com.br/dp/{asin}", UriKind.Absolute, out var amazonUri))
                {
                    var result = await TryGetAmazonDataAsync(amazonUri, ct);
                    if (result != null) return result;
                }
            }

            return null;
        }
        catch { return null; }
    }

    private async Task<List<OfficialProductDataResult>> SearchMercadoLivreMultiAsync(string title, CancellationToken ct)
    {
        var results = new List<OfficialProductDataResult>();
        if (string.IsNullOrWhiteSpace(title)) return results;

        var cacheKey = $"ml-search:{title.Trim().ToLowerInvariant()}";
        if (_memoryCache.TryGetValue(cacheKey, out List<OfficialProductDataResult>? cachedResults))
        {
            return cachedResults ?? results;
        }

        try
        {
            var searchTitle = title;
            var words = title.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (words.Length > 6) searchTitle = string.Join(" ", words.Take(6));

            var client = _httpClientFactory.CreateClient("default");
            var query = Uri.EscapeDataString(searchTitle);
            var endpoint = $"https://api.mercadolibre.com/sites/MLB/search?q={query}&limit=3";
            
            var accessToken = await _mercadoLivreOAuthService.GetAccessTokenAsync(ct);
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) return results;

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("results", out var resultsNode) || resultsNode.ValueKind != JsonValueKind.Array)
                return results;

            foreach (var first in resultsNode.EnumerateArray())
            {
                var itemId = TryGetString(first, "id");
                if (string.IsNullOrWhiteSpace(itemId)) continue;

                var res = await TryGetFromSingleUrlAsync($"https://produto.mercadolivre.com.br/{itemId}", ct);
                if (res != null) results.Add(res);
                if (results.Count >= 2) break;
            }
        }
        catch { }

        _memoryCache.Set(cacheKey, results, MercadoLivreSearchCacheTtl);
        return results;
    }

    private async Task<OfficialProductDataResult?> SearchMercadoLivreAsync(string title, CancellationToken ct)
    {
        var list = await SearchMercadoLivreMultiAsync(title, ct);
        return list.FirstOrDefault();
    }

    private async Task<OfficialProductDataResult?> SearchShopeeAsync(string title, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return null;
        }

        try
        {
            var searchTitle = title;
            var words = title.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (words.Length > 6)
            {
                searchTitle = string.Join(" ", words.Take(6));
            }

            var client = _httpClientFactory.CreateClient("default");
            var query = Uri.EscapeDataString(searchTitle);
            var endpoint = $"https://shopee.com.br/api/v4/search/search_items?by=relevancy&keyword={query}&limit=3&newest=0&order=desc&page_type=search&scenario=PAGE_GLOBAL_SEARCH&version=2";

            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
            request.Headers.TryAddWithoutValidation("Accept", "application/json,text/plain,*/*");
            request.Headers.TryAddWithoutValidation("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7");

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var item in items.EnumerateArray())
            {
                if (!item.TryGetProperty("item_basic", out var basic) || basic.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var itemId = TryGetDecimal(basic, "itemid");
                var shopId = TryGetDecimal(basic, "shopid");
                if (!itemId.HasValue || !shopId.HasValue)
                {
                    continue;
                }

                var itemIdLong = Convert.ToInt64(itemId.Value);
                var shopIdLong = Convert.ToInt64(shopId.Value);
                var targetUrl = $"https://shopee.com.br/product/{shopIdLong}/{itemIdLong}";
                var result = await TryGetShopeePublicItemDataAsync(shopIdLong, itemIdLong, targetUrl, ct);
                if (result is not null)
                {
                    return result;
                }
            }
        }
        catch
        {
        }

        return null;
    }

    private async Task<string?> TryResolveFinalUrlAsync(string? url, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var cacheKey = $"resolved-url:{url.Trim()}";
        if (_memoryCache.TryGetValue(cacheKey, out string? cachedResolvedUrl))
        {
            return cachedResolvedUrl;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var resolved = response.RequestMessage?.RequestUri?.ToString();
            _memoryCache.Set(cacheKey, resolved, ResolvedUrlCacheTtl);
            return resolved;
        }
        catch
        {
            return null;
        }
    }

    private async Task<OfficialProductDataResult?> SearchSingleStoreWithFallbackAsync(
        IReadOnlyList<string> queryVariants,
        Func<string, CancellationToken, Task<OfficialProductDataResult?>> searchFn,
        string storeName,
        List<string> logs,
        CancellationToken ct)
    {
        foreach (var query in queryVariants)
        {
            var result = await searchFn(query, ct);
            if (result is not null)
            {
                logs.Add($"Match em {storeName} com query: {query}");
                return result;
            }

            logs.Add($"Sem match em {storeName} para query: {query}");
        }

        return null;
    }

    private async Task<List<OfficialProductDataResult>> SearchMercadoLivreWithFallbackAsync(
        IReadOnlyList<string> queryVariants,
        List<string> logs,
        CancellationToken ct)
    {
        foreach (var query in queryVariants)
        {
            var results = await SearchMercadoLivreMultiAsync(query, ct);
            if (results.Count > 0)
            {
                logs.Add($"Match no Mercado Livre com query: {query}");
                return results;
            }

            logs.Add($"Sem match no Mercado Livre para query: {query}");
        }

        return new List<OfficialProductDataResult>();
    }

    private static IReadOnlyList<string> BuildSearchQueries(string rawTitle)
    {
        if (string.IsNullOrWhiteSpace(rawTitle))
        {
            return new List<string>();
        }

        var normalized = Regex.Replace(rawTitle, @"[^\p{L}\p{Nd}\s]", " ");
        var words = normalized
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(w => w.Trim())
            .Where(w => w.Length > 1)
            .ToList();

        if (words.Count == 0)
        {
            return new List<string>();
        }

        var stopWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "de", "da", "do", "dos", "das", "com", "para", "por", "sem", "na", "no", "a", "o", "e"
        };

        var compact = words.Where(w => !stopWords.Contains(w)).ToList();
        var modelLike = compact.Where(w => w.Any(char.IsDigit)).ToList();
        var descriptor = compact.Where(w => !w.Any(char.IsDigit)).Take(4).ToList();

        var queries = new List<string>
        {
            string.Join(" ", words.Take(10)),
            string.Join(" ", compact.Take(7))
        };

        if (modelLike.Count > 0)
        {
            queries.Add(string.Join(" ", modelLike.Take(3).Concat(descriptor.Take(2))));
        }

        queries.Add(string.Join(" ", words.Take(6)));

        return queries
            .Where(q => !string.IsNullOrWhiteSpace(q) && q.Length > 4)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private async Task<OfficialProductDataResult?> TryGetLinkMetaFallbackAsync(string url, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (LooksLikeImageUrl(uri.AbsoluteUri))
        {
            return new OfficialProductDataResult(
                Store: GetStoreLabel(uri.Host),
                Title: null,
                CurrentPrice: null,
                PreviousPrice: null,
                DiscountPercent: null,
                Images: new List<string> { uri.AbsoluteUri },
                IsOfficial: false,
                DataSource: "direct_image_url",
                SourceUrl: uri.AbsoluteUri,
                EstimatedDelivery: null,
                VideoUrl: null);
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            request.Headers.TryAddWithoutValidation("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7");
            request.Headers.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var finalUri = response.RequestMessage?.RequestUri ?? uri;
            var mediaType = response.Content.Headers.ContentType?.MediaType;
            if (!string.IsNullOrWhiteSpace(mediaType) && mediaType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                return new OfficialProductDataResult(
                    Store: GetStoreLabel(finalUri.Host),
                    Title: null,
                    CurrentPrice: null,
                    PreviousPrice: null,
                    DiscountPercent: null,
                    Images: new List<string> { finalUri.AbsoluteUri },
                    IsOfficial: false,
                    DataSource: "direct_image_content_type",
                    SourceUrl: finalUri.AbsoluteUri,
                    EstimatedDelivery: null,
                    VideoUrl: null);
            }

            var html = await response.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(html))
            {
                return null;
            }

            var title = FirstNonEmpty(
                ExtractMetaContent(html, "property", "og:title"),
                ExtractMetaContent(html, "name", "twitter:title"),
                ExtractMetaContent(html, "itemprop", "name"),
                ExtractTitleTag(html));

            var images = new List<string>();
            images.AddRange(ExtractMetaContents(html, "property", "og:image"));
            images.AddRange(ExtractMetaContents(html, "property", "og:image:url"));
            images.AddRange(ExtractMetaContents(html, "property", "og:image:secure_url"));
            images.AddRange(ExtractMetaContents(html, "name", "twitter:image"));
            images.AddRange(ExtractMetaContents(html, "name", "twitter:image:src"));
            images.AddRange(ExtractMetaContents(html, "itemprop", "image"));
            images = NormalizeUrls(images, finalUri)
                .Where(LooksLikeImageUrl)
                .Take(10)
                .ToList();

            if (images.Count == 0)
            {
                return null;
            }

            return new OfficialProductDataResult(
                Store: GetStoreLabel(finalUri.Host),
                Title: string.IsNullOrWhiteSpace(title) ? null : title,
                CurrentPrice: null,
                PreviousPrice: null,
                DiscountPercent: null,
                Images: images,
                IsOfficial: false,
                DataSource: "link_meta_fallback",
                SourceUrl: finalUri.AbsoluteUri,
                EstimatedDelivery: null,
                VideoUrl: null);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao extrair imagem por fallback de metadados do link. Url={Url}", url);
            return null;
        }
    }

    private static int Score(OfficialProductDataResult item)
    {
        var score = 0;
        if (item.IsOfficial) score += 100;
        if (!string.IsNullOrWhiteSpace(item.Title)) score += 35;
        if (!string.IsNullOrWhiteSpace(item.CurrentPrice)) score += 40;
        if (item.Images.Count > 0) score += 40;
        if (!string.IsNullOrWhiteSpace(item.PreviousPrice)) score += 10;
        if (item.DiscountPercent.HasValue && item.DiscountPercent.Value > 0) score += 8;
        return score;
    }

    private static string GetStoreLabel(string host)
    {
        if (IsAmazonHost(host))
        {
            return "Amazon";
        }

        if (IsMercadoLivreHost(host))
        {
            return "Mercado Livre";
        }

        if (IsShopeeHost(host))
        {
            return "Shopee";
        }

        return "Link";
    }

    private static bool LooksLikeImageUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var path = uri.AbsolutePath;
        return path.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".png", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".webp", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".gif", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".avif", StringComparison.OrdinalIgnoreCase);
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim() ?? string.Empty;

    private static string ExtractTitleTag(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        var titleTag = Regex.Match(html, "<title[^>]*>(?<value>[^<]+)</title>", RegexOptions.IgnoreCase);
        return titleTag.Success ? (WebUtility.HtmlDecode(titleTag.Groups["value"].Value)?.Trim() ?? string.Empty) : string.Empty;
    }

    private static string ExtractMetaContent(string html, string attrName, string attrValue)
        => ExtractMetaContents(html, attrName, attrValue).FirstOrDefault() ?? string.Empty;

    private static List<string> ExtractMetaContents(string html, string attrName, string attrValue)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var escapedValue = Regex.Escape(attrValue);
        var valueFirst = $@"<meta[^>]*\b{attrName}\s*=\s*['\""]{escapedValue}['\""][^>]*\bcontent\s*=\s*['\""](?<content>[^'\""]+)['\""][^>]*>";
        var contentFirst = $@"<meta[^>]*\bcontent\s*=\s*['\""](?<content>[^'\""]+)['\""][^>]*\b{attrName}\s*=\s*['\""]{escapedValue}['\""][^>]*>";
        var matches = Regex.Matches(html, $"{valueFirst}|{contentFirst}", RegexOptions.IgnoreCase);

        return matches
            .Select(m => (m.Groups["content"].Value ?? string.Empty).Trim())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => WebUtility.HtmlDecode(v) ?? string.Empty)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> NormalizeUrls(IEnumerable<string> urls, Uri? baseUri)
    {
        var list = new List<string>();
        foreach (var raw in urls)
        {
            var value = WebUtility.HtmlDecode(raw)?.Replace("\\/", "/", StringComparison.Ordinal).Trim();
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (Uri.TryCreate(value, UriKind.Absolute, out var absolute))
            {
                list.Add(absolute.ToString());
                continue;
            }

            if (baseUri is not null && Uri.TryCreate(baseUri, value, out var relative))
            {
                list.Add(relative.ToString());
            }
        }

        return list
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void AddCandidate(List<string> urls, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }
        urls.Add(value.Trim());
    }

    private async Task<string?> TryResolveShopeeShortUrlAsync(Uri uri, CancellationToken ct)
    {
        try
        {
            var shortCode = uri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(shortCode))
            {
                return null;
            }

            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://shopee.com.br/api/v4/pages/is_short_url/?path={Uri.EscapeDataString(shortCode)}");
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.TryGetProperty("data", out var dataNode) &&
                dataNode.ValueKind == JsonValueKind.Object &&
                dataNode.TryGetProperty("url", out var urlNode) &&
                urlNode.ValueKind == JsonValueKind.String)
            {
                var resolved = urlNode.GetString()?.Trim();
                return Uri.TryCreate(resolved, UriKind.Absolute, out _) ? resolved : null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao resolver short link da Shopee via API: {Url}", uri);
        }

        return null;
    }

    private static string? ExtractRedirectTargetFromHtml(string html, Uri baseUri)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return null;
        }

        var patterns = new[]
        {
            "<link[^>]+rel=[\"']canonical[\"'][^>]+href=[\"']([^\"']+)[\"']",
            "<meta[^>]+property=[\"']og:url[\"'][^>]+content=[\"']([^\"']+)[\"']",
            "<meta[^>]+name=[\"']og:url[\"'][^>]+content=[\"']([^\"']+)[\"']",
            "http-equiv=[\"']refresh[\"'][^>]*content=[\"'][^\"']*url=([^\"'>]+)",
            "location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']",
            "location\\.replace\\(\\s*[\"']([^\"']+)[\"']\\s*\\)",
            "window\\.location(?:\\.href)?\\s*=\\s*[\"']([^\"']+)[\"']"
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                continue;
            }

            var candidate = WebUtility.HtmlDecode(match.Groups[1].Value)?.Trim();
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            if (Uri.TryCreate(candidate, UriKind.Absolute, out var absolute))
            {
                return absolute.ToString();
            }

            if (Uri.TryCreate(baseUri, candidate, out var relative))
            {
                return relative.ToString();
            }
        }

        return null;
    }

    private static bool TryExtractShopeeIds(string url, out long shopId, out long itemId)
    {
        shopId = 0;
        itemId = 0;

        var match = Regex.Match(url, @"-i[._](?<shop>\d+)[._](?<item>\d+)", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            match = Regex.Match(url, @"shopee\.com\.br/[^/]+/(?<shop>\d+)/(?<item>\d+)", RegexOptions.IgnoreCase);
        }

        if (!match.Success && Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
            var shopRaw = query["shopid"] ?? query["shop_id"];
            var itemRaw = query["itemid"] ?? query["item_id"] ?? query["product_id"] ?? query["itemId"];
            if (long.TryParse(shopRaw, out shopId) && long.TryParse(itemRaw, out itemId) && shopId > 0 && itemId > 0)
            {
                return true;
            }
        }

        if (!match.Success)
        {
            return false;
        }

        return long.TryParse(match.Groups["shop"].Value, out shopId)
            && long.TryParse(match.Groups["item"].Value, out itemId)
            && shopId > 0
            && itemId > 0;
    }

    private static string BuildShopeeImageUrl(string imageHash)
        => $"https://down-br.img.susercontent.com/file/{imageHash}";

    private static string ComputeHmacSha256(string key, string data)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool IsAmazonHost(string host)
        => host.Contains("amazon.", StringComparison.OrdinalIgnoreCase)
           || host.Equals("amzn.to", StringComparison.OrdinalIgnoreCase)
           || host.Equals("a.co", StringComparison.OrdinalIgnoreCase);

    private static bool IsShopeeShortHost(string host)
    {
        var h = host.Trim().Trim('.').ToLowerInvariant();
        return h is "s.shopee.com.br" or "shopee.com.br" or "shp.ee" or "shope.ee";
    }

    private static bool IsShopeeHost(string host)
        => host.Contains("shopee", StringComparison.OrdinalIgnoreCase)
           || host.Contains("shp.ee", StringComparison.OrdinalIgnoreCase);

    private static bool IsMercadoLivreHost(string host)
        => host.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
           || host.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
           || host.Equals("meli.la", StringComparison.OrdinalIgnoreCase)
           || host.Equals("meli.co", StringComparison.OrdinalIgnoreCase);

    private static string? ExtractAmazonAsin(Uri uri)
    {
        var path = (uri.AbsolutePath ?? string.Empty).ToUpperInvariant();
        var patterns = new[]
        {
            @"/DP/(?<asin>[A-Z0-9]{10})(?:[/?]|$)",
            @"/GP/PRODUCT/(?<asin>[A-Z0-9]{10})(?:[/?]|$)",
            @"/GP/AW/D/(?<asin>[A-Z0-9]{10})(?:[/?]|$)"
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(path, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success)
            {
                return match.Groups["asin"].Value;
            }
        }

        var queryMatch = Regex.Match(uri.Query ?? string.Empty, @"(?:^|[?&])asin=(?<asin>[A-Za-z0-9]{10})(?:&|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return queryMatch.Success ? queryMatch.Groups["asin"].Value.ToUpperInvariant() : null;
    }

    private static string? ExtractMercadoLivreItemId(Uri uri)
    {
        var text = Uri.UnescapeDataString($"{uri.AbsolutePath} {uri.Query}");
        var match = Regex.Match(text, @"(?:^|[^a-zA-Z0-9])MLB[-_]?(?<id>\d{8,})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? $"MLB{match.Groups["id"].Value}" : null;
    }

    private static string? ExtractMercadoLivreItemIdFromText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = Regex.Match(text, @"\bMLB[-_]?(?<id>\d{8,})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? $"MLB{match.Groups["id"].Value}" : null;
    }

    private static long? ExtractShopeeItemId(Uri uri)
    {
        var patterns = new[]
        {
            @"i\.(?<shop>\d+)\.(?<item>\d+)",
            @"/product/(?<shop>\d+)/(?<item>\d+)",
            @"itemid=(?<item>\d+)"
        };
        foreach (var pattern in patterns)
        {
            var match = Regex.Match(uri.ToString(), pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success && long.TryParse(match.Groups["item"].Value, out var itemId))
            {
                return itemId;
            }
        }

        return null;
    }

    private static long? ExtractShopeeShopId(Uri uri)
    {
        var patterns = new[]
        {
            @"i\.(?<shop>\d+)\.(?<item>\d+)",
            @"/product/(?<shop>\d+)/(?<item>\d+)",
            @"shopid=(?<shop>\d+)"
        };
        foreach (var pattern in patterns)
        {
            var match = Regex.Match(uri.ToString(), pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success && long.TryParse(match.Groups["shop"].Value, out var shopId))
            {
                return shopId;
            }
        }

        return null;
    }

    private static string? NormalizePriceDisplay(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }

        var clean = input.Trim();
        var brl = Regex.Match(clean, @"R\$\s?\d{1,3}(?:\.\d{3})*(?:,\d{2})?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (brl.Success)
        {
            return brl.Value.Trim();
        }

        return clean;
    }

    private static string? ExtractPreviousPrice(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var matches = Regex.Matches(text, @"R\$\s?\d{1,3}(?:\.\d{3})*(?:,\d{2})?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (matches.Count >= 2)
        {
            return matches[1].Value.Trim();
        }

        return null;
    }

    private static int? ComputeDiscount(string? previousDisplay, string? currentDisplay)
    {
        var previous = ParsePriceNumber(previousDisplay);
        var current = ParsePriceNumber(currentDisplay);
        return ComputeDiscount(previous, current);
    }

    private static int? ComputeDiscount(decimal? previous, decimal? current)
    {
        if (!previous.HasValue || !current.HasValue || previous.Value <= 0 || current.Value <= 0 || previous.Value <= current.Value)
        {
            return null;
        }

        var pct = (int)Math.Round(((previous.Value - current.Value) / previous.Value) * 100m, MidpointRounding.AwayFromZero);
        return pct <= 0 ? null : pct;
    }

    private static decimal? ParsePriceNumber(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var value = Regex.Replace(text, @"[^\d\.,]", string.Empty, RegexOptions.CultureInvariant).Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (value.Contains(',', StringComparison.Ordinal) && value.Contains('.', StringComparison.Ordinal))
        {
            if (value.LastIndexOf(",", StringComparison.Ordinal) > value.LastIndexOf(".", StringComparison.Ordinal))
            {
                value = value.Replace(".", string.Empty, StringComparison.Ordinal).Replace(",", ".", StringComparison.Ordinal);
            }
            else
            {
                value = value.Replace(",", string.Empty, StringComparison.Ordinal);
            }
        }
        else if (value.Contains(',', StringComparison.Ordinal))
        {
            value = value.Replace(",", ".", StringComparison.Ordinal);
        }

        if (decimal.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static decimal? TryGetDecimal(JsonElement node, string property)
    {
        if (!node.TryGetProperty(property, out var value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetDecimal(out var number))
        {
            return number;
        }

        if (value.ValueKind == JsonValueKind.String)
        {
            var parsed = ParsePriceNumber(value.GetString());
            if (parsed.HasValue)
            {
                return parsed;
            }
        }

        return null;
    }

    private static string? TryGetString(JsonElement node, string property)
    {
        if (!node.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }
        return value.GetString();
    }

    private static int? TryGetIntPercent(JsonElement node, string property)
    {
        var raw = TryGetString(node, property);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var match = Regex.Match(raw, @"(?<v>\d{1,2})\s*%", RegexOptions.CultureInvariant);
        if (match.Success && int.TryParse(match.Groups["v"].Value, out var value))
        {
            return value;
        }

        return null;
    }

    private static decimal? NormalizeShopeePrice(decimal? value)
    {
        if (!value.HasValue)
        {
            return null;
        }

        var price = value.Value;
        if (price > 100000m)
        {
            return decimal.Round(price / 100000m, 2, MidpointRounding.AwayFromZero);
        }
        return decimal.Round(price, 2, MidpointRounding.AwayFromZero);
    }

    private static string? FormatCurrency(decimal? value, string? currency)
    {
        if (!value.HasValue)
        {
            return null;
        }

        var c = (currency ?? string.Empty).Trim().ToUpperInvariant();
        if (c is "BRL" or "R$")
        {
            return $"R$ {value.Value.ToString("N2", CultureInfo.GetCultureInfo("pt-BR"))}";
        }

        if (string.IsNullOrWhiteSpace(c))
        {
            return value.Value.ToString("N2", CultureInfo.GetCultureInfo("pt-BR"));
        }

        return $"{c} {value.Value.ToString("0.00", CultureInfo.InvariantCulture)}";
    }
}

public sealed record OfficialProductDataResult(
    string Store,
    string? Title,
    string? CurrentPrice,
    string? PreviousPrice,
    int? DiscountPercent,
    List<string> Images,
    bool IsOfficial,
    string DataSource,
    string SourceUrl,
    string? EstimatedDelivery = null,
    string? VideoUrl = null,
    bool IsLightningDeal = false,
    DateTimeOffset? LightningDealExpiry = null,
    string? CouponCode = null,
    string? CouponDescription = null,
    IReadOnlyList<PriceComparisonResult>? SearchResults = null,
    IReadOnlyList<string>? ProcessingLogs = null,
    string? SavingsDisplay = null,
    int? SavingsPercent = null,
    IReadOnlyList<string>? StoresConsulted = null,
    int? MatchesFound = null);

public sealed record PriceComparisonResult(
    string Store,
    string Title,
    string Price,
    string Url,
    string? Coupon = null);

