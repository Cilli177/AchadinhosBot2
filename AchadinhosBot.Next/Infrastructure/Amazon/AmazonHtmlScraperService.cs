using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;

namespace AchadinhosBot.Next.Infrastructure.Amazon;

/// <summary>
/// Scrapes Amazon product pages (title, price, images) without PA-API credentials.
/// Uses a 5-strategy cascade: mobile URL → desktop with real browser headers →
/// colorImages JSON → data-a-dynamic-image → og:image fallback.
/// Results are cached per ASIN for 30 minutes.
/// </summary>
public sealed class AmazonHtmlScraperService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _cache;
    private readonly ILogger<AmazonHtmlScraperService> _logger;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(30);
    private static readonly string[] UrlTemplates =
    {
        "https://www.amazon.com.br/dp/{0}?th=1&psc=1",
        "https://m.amazon.com.br/dp/{0}",
        "https://www.amazon.com.br/gp/product/{0}"
    };

    public AmazonHtmlScraperService(
        IHttpClientFactory httpClientFactory,
        IMemoryCache cache,
        ILogger<AmazonHtmlScraperService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _logger = logger;
    }

    public async Task<AmazonScrapedProduct?> ScrapeAsync(string asin, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(asin))
            return null;

        var cacheKey = $"amazon_scrape_{asin.ToUpperInvariant()}";
        if (_cache.TryGetValue(cacheKey, out AmazonScrapedProduct? cached))
            return cached;

        foreach (var template in UrlTemplates)
        {
            var url = string.Format(template, Uri.EscapeDataString(asin.ToUpperInvariant()));
            try
            {
                var result = await TryScrapeUrlAsync(url, ct);
                if (result is not null)
                {
                    _cache.Set(cacheKey, result, CacheTtl);
                    _logger.LogInformation("Amazon HTML scraper OK. ASIN={Asin} Url={Url} Title={Title} Images={Count}",
                        asin, url, result.Title, result.Images.Count);
                    return result;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Amazon HTML scraper falhou para URL={Url}", url);
            }
        }

        _logger.LogWarning("Amazon HTML scraper esgotou todas as estratégias. ASIN={Asin}", asin);
        return null;
    }

    private async Task<AmazonScrapedProduct?> TryScrapeUrlAsync(string url, CancellationToken ct)
    {
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli
        };

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Fetch-Dest", "document");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Fetch-Mode", "navigate");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Fetch-Site", "none");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Ch-Ua", "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Ch-Ua-Mobile", "?0");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Sec-Ch-Ua-Platform", "\"Windows\"");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Upgrade-Insecure-Requests", "1");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cache-Control", "max-age=0");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Connection", "keep-alive");
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");

        using var response = await client.GetAsync(url, ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogDebug("Amazon scraper URL={Url} retornou {Status}", url, (int)response.StatusCode);
            return null;
        }

        var html = await response.Content.ReadAsStringAsync(ct);
        if (string.IsNullOrWhiteSpace(html))
            return null;

        // Detect CAPTCHA / bot wall
        if (IsCaptchaPage(html))
        {
            _logger.LogDebug("Amazon scraper detectou CAPTCHA. URL={Url}", url);
            return null;
        }

        var images = ExtractImages(html);
        var title = ExtractTitle(html);
        var (price, oldPrice, discount) = ExtractPrices(html);

        if (string.IsNullOrWhiteSpace(title) && images.Count == 0)
            return null;

        return new AmazonScrapedProduct(
            Title: title,
            Price: price,
            OldPrice: oldPrice,
            DiscountPercent: discount,
            Images: images);
    }

    // ─── CAPTCHA Detection ────────────────────────────────────────────────────

    private static bool IsCaptchaPage(string html)
        => html.Contains("Type the characters you see", StringComparison.OrdinalIgnoreCase)
        || html.Contains("id=\"captchacharacters\"", StringComparison.OrdinalIgnoreCase)
        || html.Contains("Enter the characters you see below", StringComparison.OrdinalIgnoreCase)
        || html.Contains("api.solvemedia.com", StringComparison.OrdinalIgnoreCase);

    // ─── Image Extraction ─────────────────────────────────────────────────────

    private static List<string> ExtractImages(string html)
    {
        var images = new List<string>();

        // Strategy 1: colorImages JS block (most reliable, contains all high-res variants)
        ExtractColorImages(html, images);

        // Strategy 2: data-a-dynamic-image attribute on landingImage
        ExtractDynamicImage(html, images);

        // Strategy 3: data-old-hires on landingImage
        var oldHires = Regex.Match(html,
            @"id=[""']landingImage[""'][^>]*data-old-hires=[""']([^'""]+)[""']",
            RegexOptions.IgnoreCase);
        if (!oldHires.Success)
        {
            // attribute order may vary
            oldHires = Regex.Match(html,
                @"data-old-hires=[""']([^'""]+)[""'][^>]*id=[""']landingImage[""']",
                RegexOptions.IgnoreCase);
        }
        if (oldHires.Success && !string.IsNullOrWhiteSpace(oldHires.Groups[1].Value))
            TryAdd(images, oldHires.Groups[1].Value.Trim());

        // Strategy 4: og:image
        var og = Regex.Match(html,
            @"<meta[^>]*property=[""']og:image[""'][^>]*content=[""']([^'""]+)[""']",
            RegexOptions.IgnoreCase);
        if (!og.Success)
        {
            og = Regex.Match(html,
                @"<meta[^>]*content=[""']([^'""]+)[""'][^>]*property=[""']og:image[""']",
                RegexOptions.IgnoreCase);
        }
        if (og.Success)
            TryAdd(images, og.Groups[1].Value.Trim());

        // Strategy 5: all m.media-amazon.com image URLs in HTML
        foreach (Match m in Regex.Matches(html,
            @"https?:(?:\\?/){2}m\.media-amazon\.com/images/I/[^\s""'<>\\]+",
            RegexOptions.IgnoreCase))
        {
            TryAdd(images, UnescapeUrl(m.Value));
        }

        return SortByResolution(
            images
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList());
    }

    private static void ExtractColorImages(string html, List<string> images)
    {
        var colorMatch = Regex.Match(html,
            @"['""]?colorImages['""]?\s*:\s*\{\s*['""]?initial['""]?\s*:\s*(\[[\s\S]*?\])\s*\}",
            RegexOptions.IgnoreCase);

        if (!colorMatch.Success)
            return;

        var arr = colorMatch.Groups[1].Value;

        // hiRes takes priority
        foreach (Match m in Regex.Matches(arr, @"""hiRes""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase))
            TryAdd(images, UnescapeUrl(m.Groups[1].Value));

        foreach (Match m in Regex.Matches(arr, @"""large""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase))
            TryAdd(images, UnescapeUrl(m.Groups[1].Value));
    }

    private static void ExtractDynamicImage(string html, List<string> images)
    {
        // <img id="landingImage" ... data-a-dynamic-image="{&quot;https://...&quot;:[1500,1500],...}">
        var dynMatch = Regex.Match(html,
            @"id=[""']landingImage[""'][^>]*\bdata-a-dynamic-image=[""'](\{[^'""]+\})[""']",
            RegexOptions.IgnoreCase);
        if (!dynMatch.Success)
        {
            dynMatch = Regex.Match(html,
                @"\bdata-a-dynamic-image=[""'](\{[^'""]+\})[""'][^>]*id=[""']landingImage[""']",
                RegexOptions.IgnoreCase);
        }

        if (!dynMatch.Success) return;

        var json = WebUtility.HtmlDecode(dynMatch.Groups[1].Value);
        // JSON is {"url":[w,h],...} — extract keys (the URLs)
        foreach (Match m in Regex.Matches(json, @"""(https://[^""]+)""", RegexOptions.IgnoreCase))
        {
            TryAdd(images, UnescapeUrl(m.Groups[1].Value));
        }
    }

    private static List<string> SortByResolution(List<string> urls)
    {
        return urls.OrderByDescending(url =>
        {
            var m = Regex.Match(url, @"_SL(\d+)_", RegexOptions.IgnoreCase);
            return m.Success && int.TryParse(m.Groups[1].Value, out var n) ? n : 0;
        }).ToList();
    }

    private static void TryAdd(List<string> list, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        if (!Uri.TryCreate(value, UriKind.Absolute, out _)) return;
        if (!list.Contains(value, StringComparer.OrdinalIgnoreCase))
            list.Add(value);
    }

    private static string UnescapeUrl(string raw)
        => WebUtility.HtmlDecode(raw.Replace(@"\/", "/").Replace(@"\\/", "/").Trim());

    // ─── Title Extraction ─────────────────────────────────────────────────────

    private static string? ExtractTitle(string html)
    {
        // Best: <span id="productTitle">
        var spanMatch = Regex.Match(html,
            @"<span\s[^>]*id=[""']productTitle[""'][^>]*>([\s\S]*?)</span>",
            RegexOptions.IgnoreCase);
        if (spanMatch.Success)
        {
            var raw = Regex.Replace(spanMatch.Groups[1].Value, @"<[^>]+>", "").Trim();
            raw = WebUtility.HtmlDecode(raw).Trim();
            if (!string.IsNullOrWhiteSpace(raw)) return raw;
        }

        // Fallback: og:title
        var og = Regex.Match(html,
            @"<meta[^>]*property=[""']og:title[""'][^>]*content=[""']([^'""]+)[""']",
            RegexOptions.IgnoreCase);
        if (!og.Success)
        {
            og = Regex.Match(html,
                @"<meta[^>]*content=[""']([^'""]+)[""'][^>]*property=[""']og:title[""']",
                RegexOptions.IgnoreCase);
        }
        if (og.Success)
        {
            var t = WebUtility.HtmlDecode(og.Groups[1].Value).Trim();
            if (!string.IsNullOrWhiteSpace(t)) return t;
        }

        // Last resort: <title> tag, cut after first ": "
        var titleTag = Regex.Match(html, @"<title[^>]*>([^<]+)</title>", RegexOptions.IgnoreCase);
        if (titleTag.Success)
        {
            var raw = WebUtility.HtmlDecode(titleTag.Groups[1].Value).Trim();
            var colon = raw.IndexOf(": ", StringComparison.Ordinal);
            return colon > 0 ? raw[..colon].Trim() : raw;
        }

        return null;
    }

    // ─── Price Extraction ─────────────────────────────────────────────────────

    private static (string? Price, string? OldPrice, int? Discount) ExtractPrices(string html)
    {
        var prices = new List<string>();

        // Try structured price spans
        foreach (Match m in Regex.Matches(html,
            @"<span[^>]*class=[""'][^'""]*a-price[^'""]*[""'][^>]*>[\s\S]*?<span[^>]*class=[""'][^'""]*a-offscreen[^'""]*[""'][^>]*>(R\$\s?[\d.,]+)</span>",
            RegexOptions.IgnoreCase))
        {
            var p = CleanPrice(m.Groups[1].Value);
            if (!string.IsNullOrWhiteSpace(p)) prices.Add(p);
        }

        // Fallback: all R$ patterns in visible text areas
        if (prices.Count == 0)
        {
            foreach (Match m in Regex.Matches(html,
                @">R\$\s?([\d]{1,3}(?:\.[\d]{3})*(?:,[\d]{2})?)<",
                RegexOptions.IgnoreCase))
            {
                var p = $"R$ {m.Groups[1].Value.Trim()}";
                if (!prices.Contains(p)) prices.Add(p);
            }
        }

        var currentPrice = prices.Count > 0 ? prices[0] : null;
        var oldPrice = prices.Count > 1 ? prices[1] : ExtractOldPrice(html);

        // Validate: old must be higher than current
        if (!string.IsNullOrWhiteSpace(oldPrice) && !string.IsNullOrWhiteSpace(currentPrice))
        {
            var old = ParsePrice(oldPrice);
            var cur = ParsePrice(currentPrice);
            if (old.HasValue && cur.HasValue && old.Value <= cur.Value)
                oldPrice = null;
        }

        // Discount percent
        int? discount = null;
        var discountMatch = Regex.Match(html,
            @"([\d]{1,2})\s*%\s*(?:de\s*)?(?:desconto|OFF)",
            RegexOptions.IgnoreCase);
        if (discountMatch.Success && int.TryParse(discountMatch.Groups[1].Value, out var d) && d > 0 && d < 100)
            discount = d;

        if (!discount.HasValue && !string.IsNullOrWhiteSpace(oldPrice) && !string.IsNullOrWhiteSpace(currentPrice))
        {
            var old = ParsePrice(oldPrice);
            var cur = ParsePrice(currentPrice);
            if (old.HasValue && cur.HasValue && old.Value > cur.Value)
                discount = (int)Math.Round((old.Value - cur.Value) / old.Value * 100);
        }

        return (currentPrice, oldPrice, discount);
    }

    private static string? ExtractOldPrice(string html)
    {
        // basisPrice or strikethrough
        foreach (var pattern in new[]
        {
            @"basisPrice[^>]*>[\s\S]*?<span[^>]*class=[""'][^'""]*a-offscreen[^'""]*[""'][^>]*>(R\$\s?[\d.,]+)</span>",
            @"a-text-price[^>]*>[\s\S]*?<span[^>]*class=[""'][^'""]*a-offscreen[^'""]*[""'][^>]*>(R\$\s?[\d.,]+)</span>",
            @"priceBlockListPriceString[^>]*>(R\$\s?[\d.,]+)<"
        })
        {
            var m = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var p = CleanPrice(m.Groups[1].Value);
                if (!string.IsNullOrWhiteSpace(p)) return p;
            }
        }

        return null;
    }

    private static string? CleanPrice(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var clean = WebUtility.HtmlDecode(raw).Trim();
        if (!clean.StartsWith("R$", StringComparison.OrdinalIgnoreCase))
            clean = "R$ " + clean;
        return clean;
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

public sealed record AmazonScrapedProduct(
    string? Title,
    string? Price,
    string? OldPrice,
    int? DiscountPercent,
    List<string> Images);
