using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Amazon;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.ProductData;

public sealed class OfficialProductDataService
{
    private readonly AmazonPaApiClient _amazonPaApiClient;
    private readonly IMercadoLivreOAuthService _mercadoLivreOAuthService;
    private readonly AffiliateOptions _affiliateOptions;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OfficialProductDataService> _logger;

    public OfficialProductDataService(
        AmazonPaApiClient amazonPaApiClient,
        IMercadoLivreOAuthService mercadoLivreOAuthService,
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<OfficialProductDataService> logger)
    {
        _amazonPaApiClient = amazonPaApiClient;
        _mercadoLivreOAuthService = mercadoLivreOAuthService;
        _affiliateOptions = affiliateOptions.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<OfficialProductDataResult?> TryGetBestAsync(string originalUrl, string? convertedUrl, CancellationToken ct)
    {
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
                AddCandidate(resolvedCandidates, resolved);
            }
        }

        foreach (var candidate in resolvedCandidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var result = await TryGetFromSingleUrlAsync(candidate, ct);
            if (result is not null)
            {
                results.Add(result);
            }
        }

        if (results.Count == 0)
        {
            return null;
        }

        return results
            .OrderByDescending(Score)
            .FirstOrDefault();
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
        if (!_amazonPaApiClient.IsConfigured)
        {
            return null;
        }

        var asin = ExtractAmazonAsin(uri);
        if (string.IsNullOrWhiteSpace(asin))
        {
            return null;
        }

        var item = await _amazonPaApiClient.GetItemAsync(asin, ct);
        if (item is null)
        {
            return null;
        }

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
            SourceUrl: uri.ToString());
    }

    private async Task<OfficialProductDataResult?> TryGetMercadoLivreDataAsync(Uri uri, CancellationToken ct)
    {
        var itemId = await TryResolveMercadoLivreItemIdAsync(uri, ct);
        if (string.IsNullOrWhiteSpace(itemId))
        {
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
            if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
            {
                // Algumas políticas bloqueiam token inválido/expirado. Tenta chamada pública como fallback.
                using var fallbackResponse = await client.GetAsync(endpoint, ct);
                if (!fallbackResponse.IsSuccessStatusCode)
                {
                    return null;
                }

                var fallbackBody = await fallbackResponse.Content.ReadAsStringAsync(ct);
                using var fallbackDoc = JsonDocument.Parse(fallbackBody);
                return ParseMercadoLivreItemResponse(uri, fallbackDoc);
            }

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            return ParseMercadoLivreItemResponse(uri, doc);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao obter dados oficiais do Mercado Livre.");
            return null;
        }
    }

    private async Task<string?> TryResolveMercadoLivreItemIdAsync(Uri uri, CancellationToken ct)
    {
        var itemId = ExtractMercadoLivreItemId(uri);
        if (!string.IsNullOrWhiteSpace(itemId))
        {
            return itemId;
        }

        var resolved = await TryResolveFinalUrlAsync(uri.ToString(), ct);
        if (!string.IsNullOrWhiteSpace(resolved) &&
            Uri.TryCreate(resolved, UriKind.Absolute, out var resolvedUri))
        {
            itemId = ExtractMercadoLivreItemId(resolvedUri);
            if (!string.IsNullOrWhiteSpace(itemId))
            {
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
                return fromHtml;
            }
        }
        catch
        {
        }

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
            SourceUrl: uri.ToString());
    }

    private async Task<OfficialProductDataResult?> TryGetShopeeDataAsync(Uri uri, CancellationToken ct)
    {
        var settings = _affiliateOptions.ShopeeProductApi ?? new ShopeeProductApiOptions();
        if (!settings.Enabled ||
            settings.PartnerId <= 0 ||
            string.IsNullOrWhiteSpace(settings.PartnerKey))
        {
            return null;
        }

        var itemId = ExtractShopeeItemId(uri);
        var shopId = ExtractShopeeShopId(uri);
        if (itemId is null || itemId <= 0)
        {
            return null;
        }

        var path = "/api/v2/product/get_item_base_info";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var baseString = $"{settings.PartnerId}{path}{timestamp}";
        var sign = ComputeHmacSha256(settings.PartnerKey.Trim(), baseString);
        var host = string.IsNullOrWhiteSpace(settings.Host) ? "https://partner.shopeemobile.com" : settings.Host.Trim().TrimEnd('/');
        var effectiveShopId = shopId ?? settings.ShopId;
        if (effectiveShopId <= 0)
        {
            return null;
        }

        var query = new Dictionary<string, string>
        {
            ["partner_id"] = settings.PartnerId.ToString(CultureInfo.InvariantCulture),
            ["timestamp"] = timestamp.ToString(CultureInfo.InvariantCulture),
            ["sign"] = sign,
            ["shop_id"] = effectiveShopId.ToString(CultureInfo.InvariantCulture),
            ["item_id_list"] = itemId.Value.ToString(CultureInfo.InvariantCulture)
        };
        var url = $"{host}{path}?{string.Join("&", query.Select(kv => $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"))}";

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var response = await client.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (!root.TryGetProperty("response", out var responseNode) || responseNode.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (!responseNode.TryGetProperty("item_list", out var listNode) || listNode.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var first = listNode.EnumerateArray().FirstOrDefault();
            if (first.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var title = TryGetString(first, "item_name");
            var priceRaw = TryGetDecimal(first, "price");
            var previousRaw = TryGetDecimal(first, "price_before_discount");
            var normalizedPrice = NormalizeShopeePrice(priceRaw);
            var normalizedPrevious = NormalizeShopeePrice(previousRaw);
            var discount = TryGetIntPercent(first, "discount") ?? ComputeDiscount(normalizedPrevious, normalizedPrice);

            var images = new List<string>();
            var imageUrl = TryGetString(first, "image");
            if (!string.IsNullOrWhiteSpace(imageUrl))
            {
                if (Uri.TryCreate(imageUrl, UriKind.Absolute, out _))
                {
                    images.Add(imageUrl.Trim());
                }
                else
                {
                    images.Add($"https://cf.shopee.com.br/file/{imageUrl.Trim()}");
                }
            }

            if (first.TryGetProperty("image_url_list", out var listImages) && listImages.ValueKind == JsonValueKind.Array)
            {
                foreach (var node in listImages.EnumerateArray().Take(10))
                {
                    var value = node.ValueKind == JsonValueKind.String ? node.GetString() : null;
                    if (string.IsNullOrWhiteSpace(value)) continue;
                    images.Add(value.Trim());
                }
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
                DataSource: "shopee_open_api",
                SourceUrl: uri.ToString());
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao obter dados oficiais da Shopee.");
            return null;
        }
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

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            return response.RequestMessage?.RequestUri?.ToString();
        }
        catch
        {
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

    private static void AddCandidate(List<string> urls, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }
        urls.Add(value.Trim());
    }

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
        var text = $"{uri.AbsolutePath} {uri.Query}";
        var match = Regex.Match(text, @"\bMLB[-_]?(?<id>\d{8,})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
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
    string SourceUrl);
