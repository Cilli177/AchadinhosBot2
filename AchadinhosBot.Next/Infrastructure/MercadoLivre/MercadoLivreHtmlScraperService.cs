using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreScrapedProduct
{
    public string? Title { get; init; }
    public string? Price { get; init; }
    public string? OldPrice { get; init; }
    public int? DiscountPercent { get; init; }
    public List<string> Images { get; init; } = new();
    public string? Delivery { get; init; }
    public bool IsLightningDeal { get; init; }
    public string? CouponCode { get; init; }
    public string? CouponDescription { get; init; }
}

public sealed class MercadoLivreHtmlScraperService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _cache;
    private readonly ILogger<MercadoLivreHtmlScraperService> _logger;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(30);

    public MercadoLivreHtmlScraperService(
        IHttpClientFactory httpClientFactory,
        IMemoryCache cache,
        ILogger<MercadoLivreHtmlScraperService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _logger = logger;
    }

    public async Task<MercadoLivreScrapedProduct?> ScrapeUrlAsync(string url, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;

        var cacheKey = $"ml_scrape_{url.GetHashCode()}";
        if (_cache.TryGetValue(cacheKey, out MercadoLivreScrapedProduct? cached))
            return cached;

        try
        {
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                UseCookies = true, // Enable cookies as ML might use them for bot protection
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli
            };

            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Cache-Control", "max-age=0");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Ch-Ua", "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Ch-Ua-Mobile", "?0");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Ch-Ua-Platform", "\"Windows\"");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Fetch-Dest", "document");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Fetch-Mode", "navigate");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Fetch-Site", "none");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Fetch-User", "?1");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Upgrade-Insecure-Requests", "1");
            client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");

            using var response = await client.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode) return null;

            var html = await response.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(html)) return null;

            // Check for JS redirect (common in ML catalog pages)
            var redirectMatch = Regex.Match(html, @"window\.location\.href\s*=\s*'([^']+)'", RegexOptions.IgnoreCase);
            if (!redirectMatch.Success) 
                redirectMatch = Regex.Match(html, @"window\.location\.assign\s*\(\s*'([^']+)'\s*\)", RegexOptions.IgnoreCase);
            
            if (redirectMatch.Success)
            {
                var redirectUrl = redirectMatch.Groups[1].Value;
                if (!string.IsNullOrWhiteSpace(redirectUrl))
                {
                    _logger.LogDebug("ML Scraper following JS redirect: {RedirectUrl}", redirectUrl);
                    return await ScrapeUrlAsync(redirectUrl, ct);
                }
            }

            // Check for security challenge / bot block
            if (html.Contains("/security/suspicious_traffic/"))
            {
                 _logger.LogWarning("ML Scraper blocked by suspicious traffic protection for URL={Url}", url);
                 // We can't do much here without a solver or better proxying
            }

            var result = ParseHtml(html);
            if (result != null)
            {
                _cache.Set(cacheKey, result, CacheTtl);
            }
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ML HTML scraper failed for URL={Url}", url);
            return null;
        }
    }

    private MercadoLivreScrapedProduct? ParseHtml(string html)
    {
        var title = ExtractTitle(html);
        var images = ExtractImages(html);
        var (price, oldPrice, discount) = ExtractPrices(html);
        var delivery = ExtractDelivery(html);
        var isLightningDeal = ExtractLightningDeal(html);
        var (couponCode, couponDesc) = ExtractCoupons(html);

        if (string.IsNullOrWhiteSpace(title) && images.Count == 0 && string.IsNullOrWhiteSpace(price))
        {
            return null;
        }

        return new MercadoLivreScrapedProduct
        {
            Title = title,
            Price = price,
            OldPrice = oldPrice,
            DiscountPercent = discount,
            Images = images,
            Delivery = delivery,
            IsLightningDeal = isLightningDeal,
            CouponCode = couponCode,
            CouponDescription = couponDesc
        };
    }

    private static string? ExtractTitle(string html)
    {
        var match = Regex.Match(html, @"<meta\s+property=""og:title""\s+content=""([^""]+)""", RegexOptions.IgnoreCase);
        if (match.Success) return WebUtility.HtmlDecode(match.Groups[1].Value).Trim();

        match = Regex.Match(html, @"<meta\s+content=""([^""]+)""\s+property=""og:title""", RegexOptions.IgnoreCase);
        if (match.Success) return WebUtility.HtmlDecode(match.Groups[1].Value).Trim();

        match = Regex.Match(html, @"<h1\s+[^>]*class=""[^""]*ui-pdp-title[^""]*""[^>]*>([^<]+)</h1>", RegexOptions.IgnoreCase);
        if (match.Success) return WebUtility.HtmlDecode(match.Groups[1].Value).Trim();

        return null;
    }

    private static List<string> ExtractImages(string html)
    {
        var images = new List<string>();

        // 1. og:image
        foreach (Match m in Regex.Matches(html, @"<meta\s+property=""og:image""\s+content=""([^""]+)""", RegexOptions.IgnoreCase))
        {
            var url = WebUtility.HtmlDecode(m.Groups[1].Value).Trim();
            if (!images.Contains(url)) images.Add(url);
        }
        foreach (Match m in Regex.Matches(html, @"<meta\s+content=""([^""]+)""\s+property=""og:image""", RegexOptions.IgnoreCase))
        {
            var url = WebUtility.HtmlDecode(m.Groups[1].Value).Trim();
            if (!images.Contains(url)) images.Add(url);
        }

        // 2. Specific gallery images
        foreach (Match m in Regex.Matches(html, @"class=""ui-pdp-image""\s+src=""([^""]+)""", RegexOptions.IgnoreCase))
        {
             var url = WebUtility.HtmlDecode(m.Groups[1].Value).Trim();
             if (!images.Contains(url) && url.StartsWith("http")) images.Add(url);
        }

        return images;
    }

    private static (string? Price, string? OldPrice, int? Discount) ExtractPrices(string html)
    {
        string? price = null;
        string? oldPrice = null;
        int? discount = null;

        // 1. Try itemprop price (in meta or span)
        var metaPriceMatch = Regex.Match(html, @"itemprop=""price""\s+content=""([^""]+)""", RegexOptions.IgnoreCase);
        if (metaPriceMatch.Success)
        {
            if (decimal.TryParse(metaPriceMatch.Groups[1].Value, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var p))
            {
                price = $"R$ {p:N2}";
            }
        }

        // 2. Try product:price:amount
        if (string.IsNullOrWhiteSpace(price))
        {
            var amountMatch = Regex.Match(html, @"property=""product:price:amount""\s+content=""([^""]+)""", RegexOptions.IgnoreCase);
            if (!amountMatch.Success) amountMatch = Regex.Match(html, @"content=""([^""]+)""\s+property=""product:price:amount""", RegexOptions.IgnoreCase);
            
            if (amountMatch.Success && decimal.TryParse(amountMatch.Groups[1].Value, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var p))
            {
                price = $"R$ {p:N2}";
            }
        }

        // 3. Try DOM current price (andes-money-amount__fraction)
        // Targeted at poly-price (listing cards) or PDP prices
        if (string.IsNullOrWhiteSpace(price))
        {
            var curPriceMatch = Regex.Match(html, @"(?:poly-price__current|ui-pdp-price__second-line)[^>]*>.*?__fraction[^>]*>([^<]+)<", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (curPriceMatch.Success)
            {
                price = $"R$ {curPriceMatch.Groups[1].Value.Trim()}";
            }
        }

        // 4. Try getting the DOM previous price
        var oldPriceMatch = Regex.Match(html, @"(?:andes-money-amount--previous|poly-price__comparison)[^>]*>.*?__fraction[^>]*>([^<]+)<", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (oldPriceMatch.Success)
        {
             oldPrice = $"R$ {oldPriceMatch.Groups[1].Value.Trim()}";
        }

        // 5. Final fallback: just get the first fraction if we still have nothing (dangerous but better than nothing)
        if (string.IsNullOrWhiteSpace(price))
        {
             var fallbackMatch = Regex.Match(html, @"class=""andes-money-amount__fraction""[^>]*>([\d\.,]+)</span>", RegexOptions.IgnoreCase);
             if (fallbackMatch.Success)
             {
                 price = $"R$ {fallbackMatch.Groups[1].Value.Trim()}";
             }
        }

        if (price != null && oldPrice != null)
        {
            var c = ParsePrice(price);
            var o = ParsePrice(oldPrice);
            if (c.HasValue && o.HasValue && o.Value > c.Value)
            {
                discount = (int)Math.Round((o.Value - c.Value) / o.Value * 100);
            }
            if (c.HasValue && o.HasValue && c.Value >= o.Value)
            {
                oldPrice = null;
            }
        }

        return (price, oldPrice, discount);
    }

    private static string? ExtractDelivery(string html)
    {
        // 1. "Frete grátis" green text or similar
        var match = Regex.Match(html, @"ui-pdp-color--GREEN[^>]*>([^<]+)<", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            return WebUtility.HtmlDecode(match.Groups[1].Value).Trim();
        }

        // 2. Look for common shipping phrases in the whole doc
        var phrases = new[] { "Frete grátis", "Entrega grátis", "Chegará amanhã", "Chegará hoje", "Envio amanhã" };
        foreach (var phrase in phrases)
        {
             if (html.Contains(phrase, StringComparison.OrdinalIgnoreCase)) return phrase;
        }

        return null;
    }

    private static bool ExtractLightningDeal(string html)
    {
         var str = html.ToLowerInvariant();
         return str.Contains("oferta relâmpago") || str.Contains("oferta relampago");
    }

    private static (string? Code, string? Desc) ExtractCoupons(string html)
    {
        // 1. Specific Coupon Banner
        var match = Regex.Match(html, @"ui-pdp-promotions-pill[^>]*>([\s\S]*?)<", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            var text = WebUtility.HtmlDecode(match.Groups[1].Value).Trim();
            if (text.Contains("cupom", StringComparison.OrdinalIgnoreCase))
            {
                // Try to find code like XPTO20 or similar in parent container
                var codeMatch = Regex.Match(html, @"([A-Z0-9]{5,15})", RegexOptions.IgnoreCase);
                return (codeMatch.Success ? codeMatch.Groups[1].Value.ToUpperInvariant() : null, text);
            }
        }

        // 2. Coupon text pattern
        var textMatch = Regex.Match(html, @"cupom\s+de\s+(R\$\s?[\d.,]+|[\d]+%)", RegexOptions.IgnoreCase);
        if (textMatch.Success)
        {
            return (null, textMatch.Groups[0].Value);
        }

        return (null, null);
    }

    private static decimal? ParsePrice(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var digits = Regex.Replace(text, @"[^\d,.]", "").Trim();
        if (string.IsNullOrWhiteSpace(digits)) return null;
        digits = digits.Replace(".", "").Replace(",", ".");
        return decimal.TryParse(digits, System.Globalization.NumberStyles.Number,
            System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : null;
    }
}
