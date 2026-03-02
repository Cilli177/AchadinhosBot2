using System.Text.RegularExpressions;
using System.Net;
using System.Globalization;
using AchadinhosBot.Next.Infrastructure.Amazon;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramLinkMetaService
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(20);
    private static readonly object CacheLock = new();
    private static readonly Dictionary<string, CacheEntry> Cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AmazonPaApiClient _amazonPaApiClient;
    private readonly ILogger<InstagramLinkMetaService> _logger;

    public InstagramLinkMetaService(
        IHttpClientFactory httpClientFactory,
        AmazonPaApiClient amazonPaApiClient,
        ILogger<InstagramLinkMetaService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _amazonPaApiClient = amazonPaApiClient;
        _logger = logger;
    }

    public async Task<LinkMetaResult> GetMetaAsync(string link, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(link)) return new LinkMetaResult();
        if (TryGetFromCache(link, out var cached)) return cached;

        try
        {
            // ── Amazon fast-path ──────────────────────────────────────────
            LinkMetaResult? amazonMeta = null;
            if (Uri.TryCreate(link, UriKind.Absolute, out var uri) &&
                IsAmazonHost(uri.Host) &&
                _amazonPaApiClient.IsConfigured)
            {
                var asin = ExtractAmazonAsin(uri);
                if (!string.IsNullOrWhiteSpace(asin))
                {
                    var item = await _amazonPaApiClient.GetItemAsync(asin, ct);
                    if (item is not null)
                    {
                        amazonMeta = new LinkMetaResult
                        {
                            Title = item.Title,
                            PriceText = item.PriceDisplay,
                            Images = item.Images ?? new List<string>()
                        };

                        if (!string.IsNullOrWhiteSpace(amazonMeta.Title) || amazonMeta.Images.Count > 0)
                        {
                            SetCache(link, amazonMeta);
                            return amazonMeta;
                        }
                    }
                }
            }

            var client = _httpClientFactory.CreateClient("default");
            using var response = await client.GetAsync(link, ct);
            if (!response.IsSuccessStatusCode) return new LinkMetaResult();
            var html = await response.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(html)) return new LinkMetaResult();
            var resolvedUri = response.RequestMessage?.RequestUri;

            // ── Shopee: extract from embedded __NEXT_DATA__ JSON ──────────
            if (resolvedUri is not null && IsShopeeHost(resolvedUri.Host))
            {
                var shopeeResult = TryExtractShopeeMetaFromNextData(html);
                if (shopeeResult is not null)
                {
                    SetCache(link, shopeeResult);
                    return shopeeResult;
                }

                // Fallback: extract from Shopee HTML elements
                shopeeResult = TryExtractShopeeMetaFromHtml(html);
                if (shopeeResult is not null)
                {
                    SetCache(link, shopeeResult);
                    return shopeeResult;
                }
            }

            var title = FirstNonEmpty(
                amazonMeta?.Title ?? string.Empty,
                ExtractMetaContent(html, "property", "og:title"),
                ExtractMetaContent(html, "name", "twitter:title"),
                ExtractMetaContent(html, "itemprop", "name"),
                ExtractTitleTag(html));

            var description = FirstNonEmpty(
                ExtractMetaContent(html, "property", "og:description"),
                ExtractMetaContent(html, "name", "description"),
                ExtractMetaContent(html, "name", "twitter:description"));

            if (amazonMeta is null &&
                resolvedUri is not null &&
                IsAmazonHost(resolvedUri.Host) &&
                _amazonPaApiClient.IsConfigured)
            {
                var asin = ExtractAmazonAsin(resolvedUri);
                if (!string.IsNullOrWhiteSpace(asin))
                {
                    try
                    {
                        var item = await _amazonPaApiClient.GetItemAsync(asin, ct);
                        if (item is not null)
                        {
                            amazonMeta = new LinkMetaResult
                            {
                                Title = item.Title,
                                PriceText = item.PriceDisplay,
                                Images = item.Images ?? new List<string>()
                            };
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Falha ao complementar meta da Amazon via URL resolvida.");
                    }
                }
            }

            var images = new List<string>();
            if (amazonMeta?.Images is { Count: > 0 })
            {
                images.AddRange(amazonMeta.Images);
            }
            if (resolvedUri != null && IsMercadoLivreHost(resolvedUri.Host))
            {
                images.AddRange(ExtractMercadoLivreMainImageFromHtml(html));
            }
            images.AddRange(ExtractMetaContents(html, "property", "og:image"));
            images.AddRange(ExtractMetaContents(html, "property", "og:image:url"));
            images.AddRange(ExtractMetaContents(html, "property", "og:image:secure_url"));
            images.AddRange(ExtractMetaContents(html, "name", "twitter:image"));
            images.AddRange(ExtractMetaContents(html, "name", "twitter:image:src"));
            images.AddRange(ExtractMetaContents(html, "itemprop", "image"));
            images.AddRange(ExtractLinkHrefs(html, "rel", "image_src"));
            images.AddRange(ExtractImageUrlsFromJsonLd(html));
            images.AddRange(ExtractImageUrlsFromImgTags(html));
            images.AddRange(ExtractAmazonMediaImageUrls(html));
            images = NormalizeImageUrls(images, resolvedUri);

            var videos = new List<string>();
            videos.AddRange(ExtractMetaContents(html, "property", "og:video"));
            videos.AddRange(ExtractMetaContents(html, "property", "og:video:url"));
            videos.AddRange(ExtractMetaContents(html, "property", "og:video:secure_url"));
            videos.AddRange(ExtractMetaContents(html, "name", "twitter:player:stream"));
            videos.AddRange(ExtractVideoUrlsFromJsonLd(html));
            videos.AddRange(ExtractVideoUrlsFromVideoTags(html));
            videos.AddRange(ExtractVideoUrlsFromKnownJsonKeys(html));
            videos.AddRange(ExtractVideoUrlsByExtensionPattern(html));
            videos = NormalizeVideoUrls(videos, resolvedUri);

            // Extract previous price from HTML for Amazon/ML
            string previousPriceFromHtml = string.Empty;
            if (resolvedUri is not null)
            {
                var host = resolvedUri.Host.ToLowerInvariant();
                if (IsAmazonHost(host))
                {
                    previousPriceFromHtml = ExtractAmazonListPriceFromHtml(html);
                }
                else if (host.Contains("mercadolivre") || host.Contains("mercadolibre"))
                {
                    previousPriceFromHtml = ExtractMercadoLivreOldPriceFromHtml(html);
                }
            }

            var result = new LinkMetaResult
            {
                Title = WebUtility.HtmlDecode(title?.Trim() ?? string.Empty),
                Description = WebUtility.HtmlDecode(description?.Trim() ?? string.Empty),
                PriceText = FirstNonEmpty(
                    amazonMeta?.PriceText ?? string.Empty,
                    ExtractMetaPriceText(html),
                    ExtractPriceFromJsonLd(html),
                    ExtractPriceFromRawHtml(html)),
                PreviousPriceText = previousPriceFromHtml,
                DiscountPercentFromHtml = ExtractDiscountPercentFromHtml(html),
                Images = images,
                Videos = videos,
                ResolvedUrl = resolvedUri?.ToString()
            };
            SetCache(link, result);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao extrair meta do link");
            return new LinkMetaResult();
        }
    }

    private static bool IsShopeeHost(string host)
    {
        var h = host.ToLowerInvariant();
        return h.Contains("shopee") || h.Contains("shp.ee");
    }

    private static LinkMetaResult? TryExtractShopeeMetaFromNextData(string html)
    {
        // Shopee embeds product data in <script id="__NEXT_DATA__"> or window.__NEXT_DATA__
        var match = Regex.Match(
            html,
            @"<script[^>]*id=[""']__NEXT_DATA__[""'][^>]*>\s*(?<json>\{[\s\S]*?)\s*</script>",
            RegexOptions.IgnoreCase);

        if (!match.Success)
        {
            // Try alternate format
            match = Regex.Match(html,
                @"window\.__NEXT_DATA__\s*=\s*(?<json>\{[\s\S]*?)\s*;</",
                RegexOptions.IgnoreCase);
        }

        if (!match.Success) return null;

        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(match.Groups["json"].Value);
            var root = doc.RootElement;

            // Navigate: props.pageProps.initialState.pdp.data.product
            if (!root.TryGetProperty("props", out var props)) return null;
            if (!props.TryGetProperty("pageProps", out var pageProps)) return null;

            // Try multiple known paths
            System.Text.Json.JsonElement? productNode = null;

            if (pageProps.TryGetProperty("initialState", out var initState) &&
                initState.TryGetProperty("pdp", out var pdp) &&
                pdp.TryGetProperty("data", out var pdpData) &&
                pdpData.TryGetProperty("product", out var prod1))
            {
                productNode = prod1;
            }
            else if (pageProps.TryGetProperty("data", out var data) &&
                     data.TryGetProperty("product", out var prod2))
            {
                productNode = prod2;
            }
            else if (pageProps.TryGetProperty("product", out var prod3))
            {
                productNode = prod3;
            }

            if (productNode is null) return null;
            var p = productNode.Value;

            var title = p.TryGetProperty("name", out var nameNode) && nameNode.ValueKind == System.Text.Json.JsonValueKind.String
                ? nameNode.GetString()
                : null;

            // Price: Shopee stores centavos * 100000
            decimal? priceRaw = p.TryGetProperty("price", out var priceNode) && priceNode.TryGetDecimal(out var priceVal) ? priceVal : null;
            decimal? prevRaw = p.TryGetProperty("price_before_discount", out var prevNode) && prevNode.TryGetDecimal(out var prevVal) ? prevVal : null;

            static decimal? NormalizeShopeeVal(decimal? v) => v.HasValue && v.Value > 100000 ? Math.Round(v.Value / 100000m, 2) : v;
            var price = NormalizeShopeeVal(priceRaw);
            var prev = NormalizeShopeeVal(prevRaw);

            string? priceText = price.HasValue ? $"R$ {price.Value:N2}" : null;

            // Images
            var images = new List<string>();
            if (p.TryGetProperty("images", out var imagesArr) && imagesArr.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var img in imagesArr.EnumerateArray().Take(8))
                {
                    var imgUrl = img.ValueKind == System.Text.Json.JsonValueKind.String ? img.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(imgUrl))
                    {
                        images.Add(imgUrl.StartsWith("http") ? imgUrl : $"https://cf.shopee.com.br/file/{imgUrl}");
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(priceText) && images.Count == 0)
                return null;

            return new LinkMetaResult
            {
                Title = WebUtility.HtmlDecode(title?.Trim() ?? string.Empty),
                PriceText = priceText ?? string.Empty,
                Images = images
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Fallback: extract Shopee product data from raw HTML elements when __NEXT_DATA__ is unavailable.
    /// </summary>
    private static LinkMetaResult? TryExtractShopeeMetaFromHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html)) return null;

        try
        {
            var decoded = WebUtility.HtmlDecode(html) ?? html;

            // Title: try h1 tag first, then OG title
            string? title = null;
            var h1Match = Regex.Match(decoded, @"<h1[^>]*>(.*?)</h1>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (h1Match.Success)
            {
                title = Regex.Replace(h1Match.Groups[1].Value, @"<[^>]+>", "").Trim();
            }
            if (string.IsNullOrWhiteSpace(title))
            {
                title = ExtractMetaContent(html, "property", "og:title");
            }

            // Images: extract susercontent.com URLs (Shopee CDN)
            var images = new List<string>();
            var imgMatches = Regex.Matches(decoded,
                @"https?://(?:down-br\.img\.susercontent\.com|cf\.shopee\.com\.br)/file/[^\s""'<>]+",
                RegexOptions.IgnoreCase);
            foreach (Match m in imgMatches)
            {
                var imgUrl = m.Value.TrimEnd('.', ',', ')', ']', '}');
                // Remove resize suffixes to get original
                var cleanUrl = Regex.Replace(imgUrl, @"@resize_w\d+(?:_nl)?$", "", RegexOptions.IgnoreCase);
                if (!string.IsNullOrWhiteSpace(cleanUrl) && !images.Contains(cleanUrl, StringComparer.OrdinalIgnoreCase))
                {
                    images.Add(cleanUrl);
                }
            }

            // Also try OG image
            var ogImage = ExtractMetaContent(html, "property", "og:image");
            if (!string.IsNullOrWhiteSpace(ogImage) && !images.Contains(ogImage, StringComparer.OrdinalIgnoreCase))
            {
                images.Insert(0, ogImage);
            }

            // Price: try R$ pattern from HTML
            string? priceText = null;
            var priceMatch = Regex.Match(decoded,
                @"R\$\s?(?<price>\d{1,3}(?:\.\d{3})*(?:,\d{2})?)",
                RegexOptions.IgnoreCase);
            if (priceMatch.Success)
            {
                priceText = $"R$ {priceMatch.Groups["price"].Value.Trim()}";
            }
            if (string.IsNullOrWhiteSpace(priceText))
            {
                priceText = ExtractMetaPriceText(html);
            }

            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(priceText) && images.Count == 0)
                return null;

            return new LinkMetaResult
            {
                Title = title?.Trim() ?? string.Empty,
                PriceText = priceText ?? string.Empty,
                Images = images.Take(8).ToList()
            };
        }
        catch
        {
            return null;
        }
    }


    private static bool TryGetFromCache(string link, out LinkMetaResult result)
    {
        lock (CacheLock)
        {
            if (Cache.TryGetValue(link, out var entry))
            {
                if (DateTimeOffset.UtcNow - entry.Timestamp <= CacheTtl)
                {
                    result = entry.Result;
                    return true;
                }
                Cache.Remove(link);
            }
        }
        result = new LinkMetaResult();
        return false;
    }

    private static void SetCache(string link, LinkMetaResult result)
    {
        lock (CacheLock)
        {
            Cache[link] = new CacheEntry(DateTimeOffset.UtcNow, result);
        }
    }

    private static string FirstNonEmpty(params string[] values)
        => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? string.Empty;

    private static bool IsAmazonHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var normalized = host.Trim().ToLowerInvariant();
        return normalized == "amazon.com"
               || normalized == "amazon.com.br"
               || normalized.EndsWith(".amazon.com", StringComparison.Ordinal)
               || normalized.EndsWith(".amazon.com.br", StringComparison.Ordinal);
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

    private static string ExtractTitleTag(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        var titleTag = Regex.Match(html, "<title[^>]*>(?<value>[^<]+)</title>", RegexOptions.IgnoreCase);
        return titleTag.Success ? (titleTag.Groups["value"].Value ?? string.Empty).Trim() : string.Empty;
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
        var valueFirst = $@"<meta[^>]*\b{attrName}\s*=\s*['""]{escapedValue}['""][^>]*\bcontent\s*=\s*['""](?<content>[^'""]+)['""][^>]*>";
        var contentFirst = $@"<meta[^>]*\bcontent\s*=\s*['""](?<content>[^'""]+)['""][^>]*\b{attrName}\s*=\s*['""]{escapedValue}['""][^>]*>";
        var matches = Regex.Matches(html, $"{valueFirst}|{contentFirst}", RegexOptions.IgnoreCase);

        return matches
            .Select(m => (m.Groups["content"].Value ?? string.Empty).Trim())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => WebUtility.HtmlDecode(v) ?? string.Empty)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ExtractLinkHrefs(string html, string attrName, string attrValue)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var escapedValue = Regex.Escape(attrValue);
        var valueFirst = $@"<link[^>]*\b{attrName}\s*=\s*['""]{escapedValue}['""][^>]*\bhref\s*=\s*['""](?<href>[^'""]+)['""][^>]*>";
        var hrefFirst = $@"<link[^>]*\bhref\s*=\s*['""](?<href>[^'""]+)['""][^>]*\b{attrName}\s*=\s*['""]{escapedValue}['""][^>]*>";
        var matches = Regex.Matches(html, $"{valueFirst}|{hrefFirst}", RegexOptions.IgnoreCase);

        return matches
            .Select(m => (m.Groups["href"].Value ?? string.Empty).Trim())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => WebUtility.HtmlDecode(v) ?? string.Empty)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ExtractImageUrlsFromJsonLd(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var list = new List<string>();
        var scripts = Regex.Matches(
            html,
            @"<script[^>]*type\s*=\s*['""]application/ld\+json['""][^>]*>(?<json>[\s\S]*?)</script>",
            RegexOptions.IgnoreCase);

        foreach (Match script in scripts)
        {
            var json = script.Groups["json"].Value;
            if (string.IsNullOrWhiteSpace(json))
            {
                continue;
            }

            list.AddRange(ExtractJsonImageByKey(json, "image"));
            list.AddRange(ExtractJsonImageByKey(json, "contentUrl"));
            list.AddRange(ExtractJsonImageByKey(json, "thumbnailUrl"));
        }

        return list
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IEnumerable<string> ExtractJsonImageByKey(string json, string key)
    {
        var escapedKey = Regex.Escape(key);

        // "image":"https://..."
        var scalarPattern = $@"""{escapedKey}""\s*:\s*""(?<url>[^""]+)""";
        foreach (Match match in Regex.Matches(json, scalarPattern, RegexOptions.IgnoreCase))
        {
            var raw = match.Groups["url"].Value;
            if (!string.IsNullOrWhiteSpace(raw))
            {
                yield return UnescapeJsonUrl(raw);
            }
        }

        // "image":["https://...","https://..."]
        var arrayPattern = $@"""{escapedKey}""\s*:\s*\[(?<arr>[\s\S]*?)\]";
        foreach (Match arrayMatch in Regex.Matches(json, arrayPattern, RegexOptions.IgnoreCase))
        {
            var arr = arrayMatch.Groups["arr"].Value;
            if (string.IsNullOrWhiteSpace(arr))
            {
                continue;
            }

            foreach (Match m in Regex.Matches(arr, @"""(?<url>[^""]+)""", RegexOptions.IgnoreCase))
            {
                var raw = m.Groups["url"].Value;
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    yield return UnescapeJsonUrl(raw);
                }
            }
        }
    }

    private static string UnescapeJsonUrl(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var result = value
            .Replace(@"\/", "/", StringComparison.Ordinal)
            .Replace(@"\u002F", "/", StringComparison.OrdinalIgnoreCase)
            .Replace(@"\u003A", ":", StringComparison.OrdinalIgnoreCase);

        return WebUtility.HtmlDecode(result)?.Trim() ?? string.Empty;
    }

    private static List<string> ExtractImageUrlsFromImgTags(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var urls = new List<string>();
        var imgTags = Regex.Matches(html, @"<img\b[^>]*>", RegexOptions.IgnoreCase);

        foreach (Match match in imgTags)
        {
            var tag = match.Value ?? string.Empty;
            if (string.IsNullOrWhiteSpace(tag))
            {
                continue;
            }

            if (IsTinyImageTag(tag))
            {
                continue;
            }

            foreach (var attr in new[] { "src", "data-src", "data-original", "data-image", "data-lazy-src", "data-ks-lazyload" })
            {
                var value = ExtractTagAttribute(tag, attr);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    urls.Add(value!);
                }
            }

            var srcset = ExtractTagAttribute(tag, "srcset");
            if (!string.IsNullOrWhiteSpace(srcset))
            {
                urls.AddRange(ParseSrcSet(srcset!));
            }
        }

        return urls
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ExtractAmazonMediaImageUrls(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var list = new List<string>();

        // Priority 1: Main product "landingImage"
        var landingMatch = Regex.Match(
            html,
            @"<img[^>]*?(?:id|data-a-image-name)=[""']landingImage['""][^>]*>",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        if (landingMatch.Success)
        {
            var imgTag = landingMatch.Value;
            var hiResMatch = Regex.Match(imgTag, @"data-old-hires=[""']([^'""]+)['""]", RegexOptions.IgnoreCase);
            if (hiResMatch.Success && !string.IsNullOrWhiteSpace(hiResMatch.Groups[1].Value))
            {
                list.Add(UnescapeJsonUrl(hiResMatch.Groups[1].Value));
            }
            
            var srcMatch = Regex.Match(imgTag, @"src=[""']([^'""]+)['""]", RegexOptions.IgnoreCase);
            if (srcMatch.Success && !string.IsNullOrWhiteSpace(srcMatch.Groups[1].Value))
            {
                list.Add(UnescapeJsonUrl(srcMatch.Groups[1].Value));
            }
        }

        var absolute = Regex.Matches(
            html,
            @"https?:\\?/\\?/m\.media-amazon\.com/images/I/[^""'<>\\s]+",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (Match match in absolute)
        {
            var raw = match.Value;
            if (!string.IsNullOrWhiteSpace(raw))
            {
                list.Add(UnescapeJsonUrl(raw));
            }
        }

        var encoded = Regex.Matches(
            html,
            @"m\.media-amazon\.com/images/I/[^""'<>\\s]+",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (Match match in encoded)
        {
            var raw = match.Value;
            if (!string.IsNullOrWhiteSpace(raw))
            {
                list.Add($"https://{raw.Trim()}");
            }
        }

        return list
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ExtractMercadoLivreMainImageFromHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var decoded = WebUtility.HtmlDecode(html)?.Replace('\u00A0', ' ') ?? html;

        // Try data-zoom attribute from img with ui-pdp-gallery__figure__image class (highest res)
        var imgDirectMatch = Regex.Match(
            decoded,
            @"<img[^>]*class=""[^""]*ui-pdp-gallery__figure__image[^""]*""[^>]*data-zoom\s*=\s*['""]([^'""]+)['""]",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (imgDirectMatch.Success)
        {
            return new List<string> { imgDirectMatch.Groups[1].Value.Trim() };
        }

        // Fallback: data-zoom or src from same class
        var imgSrcMatch = Regex.Match(
            decoded,
            @"<img[^>]*class=""[^""]*ui-pdp-gallery__figure__image[^""]*""[^>]*src\s*=\s*['""]([^'""]+)['""]",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (imgSrcMatch.Success)
        {
            return new List<string> { imgSrcMatch.Groups[1].Value.Trim() };
        }

        // Legacy: try to get the high-res image from the main gallery figure container
        var galleryMatch = Regex.Match(
            decoded,
            @"ui-pdp-gallery__figure[^>]*>.*?<img[^>]*?(?:data-zoom|src)\s*=\s*['""]([^'""]+)['""]",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);

        if (galleryMatch.Success)
        {
            return new List<string> { galleryMatch.Groups[1].Value.Trim() };
        }

        return new List<string>();
    }

    private static List<string> ExtractVideoUrlsFromVideoTags(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var urls = new List<string>();
        var videoTags = Regex.Matches(html, @"<video\b[^>]*>(?<inner>[\s\S]*?)</video>", RegexOptions.IgnoreCase);
        foreach (Match match in videoTags)
        {
            var tag = match.Value ?? string.Empty;
            var src = ExtractTagAttribute(tag, "src");
            if (!string.IsNullOrWhiteSpace(src))
            {
                urls.Add(src!);
            }

            var inner = match.Groups["inner"].Value ?? string.Empty;
            foreach (Match source in Regex.Matches(inner, @"<source\b[^>]*>", RegexOptions.IgnoreCase))
            {
                var sourceSrc = ExtractTagAttribute(source.Value, "src");
                if (!string.IsNullOrWhiteSpace(sourceSrc))
                {
                    urls.Add(sourceSrc!);
                }
            }
        }

        var sourceOnly = Regex.Matches(html, @"<source\b[^>]*>", RegexOptions.IgnoreCase);
        foreach (Match source in sourceOnly)
        {
            var sourceSrc = ExtractTagAttribute(source.Value, "src");
            if (!string.IsNullOrWhiteSpace(sourceSrc))
            {
                urls.Add(sourceSrc!);
            }
        }

        return urls
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ExtractVideoUrlsFromJsonLd(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var list = new List<string>();
        var scripts = Regex.Matches(
            html,
            @"<script[^>]*type\s*=\s*['""]application/ld\+json['""][^>]*>(?<json>[\s\S]*?)</script>",
            RegexOptions.IgnoreCase);

        foreach (Match script in scripts)
        {
            var json = script.Groups["json"].Value;
            if (string.IsNullOrWhiteSpace(json))
            {
                continue;
            }

            list.AddRange(ExtractJsonImageByKey(json, "contentUrl"));
            list.AddRange(ExtractJsonImageByKey(json, "embedUrl"));
            list.AddRange(ExtractJsonImageByKey(json, "video"));
        }

        return list
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ExtractVideoUrlsFromKnownJsonKeys(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var keys = new[]
        {
            "videoUrl",
            "video_url",
            "playUrl",
            "play_url",
            "streamUrl",
            "stream_url",
            "hlsUrl",
            "hls_url",
            "masterUrl",
            "master_url",
            "downloadUrl",
            "download_url",
            "video"
        };

        var list = new List<string>();
        foreach (var key in keys)
        {
            list.AddRange(ExtractJsonImageByKey(html, key));
        }

        return list
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ExtractVideoUrlsByExtensionPattern(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return new List<string>();
        }

        var list = new List<string>();
        var absolutePattern = @"https?:\\?/\\?/[^""'<>\\s]+?\.(?:mp4|mov|m4v|webm|m3u8)(?:\?[^""'<>\\s]*)?";
        foreach (Match match in Regex.Matches(html, absolutePattern, RegexOptions.IgnoreCase))
        {
            var raw = match.Value;
            if (!string.IsNullOrWhiteSpace(raw))
            {
                list.Add(UnescapeJsonUrl(raw));
            }
        }

        var relativePattern = @"(?:\\?/)+[^""'<>\\s]+?\.(?:mp4|mov|m4v|webm|m3u8)(?:\?[^""'<>\\s]*)?";
        foreach (Match match in Regex.Matches(html, relativePattern, RegexOptions.IgnoreCase))
        {
            var raw = match.Value;
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var normalized = UnescapeJsonUrl(raw);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                list.Add(normalized);
            }
        }

        return list
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool IsTinyImageTag(string tag)
    {
        var widthRaw = ExtractTagAttribute(tag, "width");
        var heightRaw = ExtractTagAttribute(tag, "height");
        if (int.TryParse(widthRaw, out var width) && int.TryParse(heightRaw, out var height))
        {
            return width > 0 && height > 0 && width <= 120 && height <= 120;
        }

        var lower = tag.ToLowerInvariant();
        return lower.Contains("icon", StringComparison.OrdinalIgnoreCase)
               || lower.Contains("avatar", StringComparison.OrdinalIgnoreCase)
               || lower.Contains("sprite", StringComparison.OrdinalIgnoreCase);
    }

    private static string? ExtractTagAttribute(string tag, string attrName)
    {
        if (string.IsNullOrWhiteSpace(tag) || string.IsNullOrWhiteSpace(attrName))
        {
            return null;
        }

        var escaped = Regex.Escape(attrName);
        var quoted = Regex.Match(tag, $@"\b{escaped}\s*=\s*['""](?<v>[^'""]+)['""]", RegexOptions.IgnoreCase);
        if (quoted.Success)
        {
            return WebUtility.HtmlDecode(quoted.Groups["v"].Value)?.Trim();
        }

        var unquoted = Regex.Match(tag, $@"\b{escaped}\s*=\s*(?<v>[^\s>]+)", RegexOptions.IgnoreCase);
        if (unquoted.Success)
        {
            return WebUtility.HtmlDecode(unquoted.Groups["v"].Value)?.Trim();
        }

        return null;
    }

    private static IEnumerable<string> ParseSrcSet(string srcset)
    {
        if (string.IsNullOrWhiteSpace(srcset))
        {
            yield break;
        }

        var parts = srcset.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var token = part.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(token))
            {
                yield return token;
            }
        }
    }

    private static List<string> NormalizeImageUrls(IEnumerable<string> urls, Uri? baseUri)
    {
        var result = new List<string>();
        foreach (var raw in urls.Where(x => !string.IsNullOrWhiteSpace(x)).Take(80))
        {
            var value = (raw ?? string.Empty).Trim().Trim('"', '\'');
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }
            if (value.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("blob:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            value = WebUtility.HtmlDecode(value)?.Trim() ?? string.Empty;

            if (value.StartsWith("//", StringComparison.Ordinal))
            {
                value = (baseUri?.Scheme ?? "https") + ":" + value;
            }

            if (Uri.TryCreate(value, UriKind.Absolute, out var absolute))
            {
                if (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)
                {
                    result.Add(absolute.GetLeftPart(UriPartial.Path) + absolute.Query);
                }
                continue;
            }

            if (baseUri is not null && Uri.TryCreate(baseUri, value, out var relative) &&
                (relative.Scheme == Uri.UriSchemeHttp || relative.Scheme == Uri.UriSchemeHttps))
            {
                result.Add(relative.GetLeftPart(UriPartial.Path) + relative.Query);
            }
        }

        return result
            .Where(x => !IsLikelyInvalidImageUrl(x))
            .Select(UpgradeAmazonImageUrl)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();
    }

    /// <summary>
    /// Upgrade Amazon thumbnail URLs to high-resolution versions.
    /// Transforms suffixes like _AC_US40_, _SX38_, _SS100_ to _AC_SL1200_.
    /// </summary>
    private static string UpgradeAmazonImageUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return url;
        if (!url.Contains("media-amazon.com", StringComparison.OrdinalIgnoreCase) &&
            !url.Contains("images-amazon.com", StringComparison.OrdinalIgnoreCase))
            return url;

        // Replace sizing suffixes like ._AC_US40_. or ._SX38_SY50_CR,0,0,38,50_. etc with ._AC_SL1200_.
        return Regex.Replace(url,
            @"\._[A-Z]{2}[^.]*_\.",
            "._AC_SL1200_.",
            RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Extract old/list price from Amazon HTML (the strikethrough price).
    /// </summary>
    private static string ExtractAmazonListPriceFromHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html)) return string.Empty;
        var decoded = WebUtility.HtmlDecode(html)?.Replace('\u00A0', ' ') ?? html;

        // Amazon uses class "a-text-price" for the old (crossed-out) prices
        var listPriceMatch = Regex.Match(decoded,
            @"a-text-price[^>]*>\s*<span[^>]*>\s*R\$\s*(?<price>\d{1,3}(?:[\.]\d{3})*(?:,\d{2})?)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (listPriceMatch.Success)
        {
            return $"R$ {listPriceMatch.Groups["price"].Value.Trim()}";
        }

        // Alternative: basisPrice, priceBlockStrikePriceString
        var altMatch = Regex.Match(decoded,
            @"(?:basisPrice|priceBlockStrikePriceString|list_price)[^>]*>.*?R\$\s*(?<price>\d{1,3}(?:[\.]\d{3})*(?:,\d{2})?)",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (altMatch.Success)
        {
            return $"R$ {altMatch.Groups["price"].Value.Trim()}";
        }

        // Amazon aria-hidden spans near savingsPercentage: <span aria-hidden="true">R$212,00</span>
        var ariaMatch = Regex.Match(decoded,
            @"savingsPercentage.*?<span[^>]*aria-hidden[^>]*>\s*R\$\s*(?<price>\d{1,3}(?:[\.]\d{3})*(?:,\d{2})?)",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (ariaMatch.Success)
        {
            return $"R$ {ariaMatch.Groups["price"].Value.Trim()}";
        }

        return string.Empty;
    }

    /// <summary>
    /// Extract Mercado Livre old price from HTML (the strikethrough price).
    /// </summary>
    private static string ExtractMercadoLivreOldPriceFromHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html)) return string.Empty;
        var decoded = WebUtility.HtmlDecode(html)?.Replace('\u00A0', ' ') ?? html;

        // Isolate the main product price block based on user hints (e.g. id="price" or ui-pdp-price class)
        var mainPriceBlockMatch = Regex.Match(decoded,
            @"(?:id=""price""|class=""[^""]*ui-pdp-price[^""]*"").*?(?:andes-money-amount--previous[^>]*>.*?R\$\s*(?<price>\d{1,3}(?:[\.]\d{3})*(?:,\d{2})?))",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);

        if (mainPriceBlockMatch.Success) return $"R$ {mainPriceBlockMatch.Groups["price"].Value.Trim()}";

        // Fallback to strict first occurrence of previous price if container logic fails
        var match = Regex.Match(decoded,
            @"andes-money-amount--previous[^>]*>.*?R\$\s*(?<price>\d{1,3}(?:[\.]\d{3})*(?:,\d{2})?)",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (match.Success) return $"R$ {match.Groups["price"].Value.Trim()}";

        var altMatch = Regex.Match(decoded,
            @"price-tag[_-]?(?:striked|old|original)[^>]*>.*?R\$\s*(?<price>\d{1,3}(?:[\.]\d{3})*(?:,\d{2})?)",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (altMatch.Success) return $"R$ {altMatch.Groups["price"].Value.Trim()}";

        return string.Empty;
    }

    /// <summary>
    /// Isolate the main product price block based on user hints (e.g. id="price" or ui-pdp-price class)
    /// </summary>
    private static string IsolateMercadoLivrePriceBlock(string decodedHtml)
    {
        var mainPriceBlockMatch = Regex.Match(decodedHtml,
            @"(?:id=""price""|class=""[^""]*ui-pdp-price[^""]*"").*?(?:</div></div>|</div>\s*</div>)",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);

        if (mainPriceBlockMatch.Success)
        {
            return mainPriceBlockMatch.Value;
        }
        
        // Return a reasonable chunk if the strict block fails
        var fallbackMatch = Regex.Match(decodedHtml, 
            @"ui-pdp-price[^""]*"".*?<button", 
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
            
        return fallbackMatch.Success ? fallbackMatch.Value : decodedHtml;
    }

    /// <summary>
    /// Extract discount percentage directly from the HTML (e.g. '25% OFF', '-25%', '25% de desconto').
    /// </summary>
    private static int? ExtractDiscountPercentFromHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html)) return null;
        var decoded = WebUtility.HtmlDecode(html)?.Replace('\u00A0', ' ') ?? html;

        // If it looks like Mercado Livre, restrict search to the main price block
        if (decoded.Contains("mercadolivre.com") || decoded.Contains("mercadolibre.com") || decoded.Contains("ui-pdp-price"))
        {
            decoded = IsolateMercadoLivrePriceBlock(decoded);
        }

        // Amazon-specific: savingsPercentage class with "-44%" pattern
        var amazonMatch = Regex.Match(decoded,
            @"savingsPercentage[^>]*>\s*[-−]\s*(?<pct>\d{1,2})\s*%",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (amazonMatch.Success && int.TryParse(amazonMatch.Groups["pct"].Value, out var amazonPct) && amazonPct > 0 && amazonPct < 100)
            return amazonPct;

        // Match patterns: "25% OFF", "-25%", "25% de desconto", "25% off", "Economize 25%"
        var match = Regex.Match(decoded,
            @"(?:[-−]\s*)?(?<pct>\d{1,2})\s*%\s*(?:OFF|off|de desconto|desconto)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (match.Success && int.TryParse(match.Groups["pct"].Value, out var pct) && pct > 0 && pct < 100)
            return pct;

        // Also try: "Economize 25%" or "economize R$... (25%)"
        var altMatch = Regex.Match(decoded,
            @"(?:economize|desconto|oferta)\s.*?(?<pct>\d{1,2})\s*%",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (altMatch.Success && int.TryParse(altMatch.Groups["pct"].Value, out var pct2) && pct2 > 0 && pct2 < 100)
            return pct2;

        // Generic standalone: "-44%" anywhere in the HTML
        var standaloneMatch = Regex.Match(decoded,
            @"[-−]\s*(?<pct>\d{1,2})\s*%",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (standaloneMatch.Success && int.TryParse(standaloneMatch.Groups["pct"].Value, out var pct3) && pct3 > 0 && pct3 < 100)
            return pct3;

        return null;
    }

    private static List<string> NormalizeVideoUrls(IEnumerable<string> urls, Uri? baseUri)
    {
        var result = new List<string>();
        foreach (var raw in urls.Where(x => !string.IsNullOrWhiteSpace(x)).Take(80))
        {
            var value = (raw ?? string.Empty).Trim().Trim('"', '\'');
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }
            if (value.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("blob:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            value = WebUtility.HtmlDecode(value)?.Trim() ?? string.Empty;
            if (value.StartsWith("//", StringComparison.Ordinal))
            {
                value = (baseUri?.Scheme ?? "https") + ":" + value;
            }

            if (Uri.TryCreate(value, UriKind.Absolute, out var absolute))
            {
                if (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)
                {
                    result.Add(absolute.GetLeftPart(UriPartial.Path) + absolute.Query);
                }
                continue;
            }

            if (baseUri is not null &&
                Uri.TryCreate(baseUri, value, out var relative) &&
                (relative.Scheme == Uri.UriSchemeHttp || relative.Scheme == Uri.UriSchemeHttps))
            {
                result.Add(relative.GetLeftPart(UriPartial.Path) + relative.Query);
            }
        }

        return result
            .Where(x => !IsLikelyInvalidVideoUrl(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
    }

    private static bool IsLikelyInvalidImageUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return true;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return true;
        }

        var path = uri.AbsolutePath.ToLowerInvariant();
        var host = uri.Host.ToLowerInvariant();
        if (path.EndsWith(".svg", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (host.StartsWith("fls-na.", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("oc-csi", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("/images/g/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return path.Contains("logo", StringComparison.OrdinalIgnoreCase)
               || path.Contains("sprite", StringComparison.OrdinalIgnoreCase)
               || path.Contains("icon", StringComparison.OrdinalIgnoreCase)
               || path.Contains("avatar", StringComparison.OrdinalIgnoreCase)
               || path.Contains("placeholder", StringComparison.OrdinalIgnoreCase)
               || path.Contains("loading", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsMercadoLivreHost(string host)
        => host.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
           || host.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
           || host.Equals("meli.la", StringComparison.OrdinalIgnoreCase)
           || host.Equals("meli.co", StringComparison.OrdinalIgnoreCase);

    private static bool IsLikelyInvalidVideoUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return true;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return true;
        }

        var path = uri.AbsolutePath.ToLowerInvariant();
        if (path.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".webp", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".gif", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (path.Contains("logo", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("sprite", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("icon", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static string ExtractMetaPriceText(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        var amount = FirstNonEmpty(
            ExtractMetaContent(html, "property", "product:price:amount"),
            ExtractMetaContent(html, "property", "og:price:amount"),
            ExtractMetaContent(html, "name", "product:price:amount"),
            ExtractMetaContent(html, "itemprop", "price"),
            ExtractMetaContent(html, "name", "price"));
        var currency = FirstNonEmpty(
            ExtractMetaContent(html, "property", "product:price:currency"),
            ExtractMetaContent(html, "property", "og:price:currency"),
            ExtractMetaContent(html, "name", "product:price:currency"),
            ExtractMetaContent(html, "itemprop", "priceCurrency"));

        var formatted = FormatPriceDisplay(amount, currency);
        if (!string.IsNullOrWhiteSpace(formatted))
        {
            return formatted;
        }

        return string.Empty;
    }

    private static string ExtractPriceFromJsonLd(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        var currencyMatch = Regex.Match(
            html,
            @"""(?:priceCurrency|currency)""\s*:\s*""(?<currency>[A-Z]{3})""",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var priceMatch = Regex.Match(
            html,
            @"""(?:price|lowPrice|highPrice)""\s*:\s*""?(?<price>\d{1,7}(?:[.,]\d{1,2})?)""?",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        if (!priceMatch.Success)
        {
            return string.Empty;
        }

        var priceRaw = priceMatch.Groups["price"].Value;
        var currency = currencyMatch.Success ? currencyMatch.Groups["currency"].Value : string.Empty;
        return FormatPriceDisplay(priceRaw, currency);
    }

    private static string ExtractPriceFromRawHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        var decoded = WebUtility.HtmlDecode(html)?.Replace('\u00A0', ' ') ?? html;

        // If it looks like Mercado Livre, restrict search to the main price block
        if (decoded.Contains("mercadolivre.com") || decoded.Contains("mercadolibre.com") || decoded.Contains("ui-pdp-price"))
        {
            var mlBlock = IsolateMercadoLivrePriceBlock(decoded);
            
            // Extract whole and cents from the exact structure the user provided
            var mlWhole = Regex.Match(mlBlock, @"andes-money-amount__fraction[^>]*>(?<whole>\d{1,3}(?:[\.]\d{3})*)", RegexOptions.IgnoreCase);
            var mlCents = Regex.Match(mlBlock, @"andes-money-amount__cents[^>]*>(?<cents>\d{1,2})", RegexOptions.IgnoreCase);
            
            if (mlWhole.Success)
            {
                var cents = mlCents.Success ? mlCents.Groups["cents"].Value : "00";
                return $"R$ {mlWhole.Groups["whole"].Value},{cents}";
            }
        }

        var amazonWhole = Regex.Match(
            decoded,
            @"a-price-whole[^>]*>\s*(?<whole>\d{1,3}(?:[\.]\d{3})*)\s*<",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var amazonFraction = Regex.Match(
            decoded,
            @"a-price-fraction[^>]*>\s*(?<fraction>\d{2})\s*<",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (amazonWhole.Success && amazonFraction.Success)
        {
            return $"R$ {amazonWhole.Groups["whole"].Value.Trim()},{amazonFraction.Groups["fraction"].Value.Trim()}";
        }

        var brl = Regex.Match(
            decoded,
            @"R\$\s?(?<price>\d{1,3}(?:\.\d{3})*(?:,\d{2})?)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (brl.Success)
        {
            return $"R$ {brl.Groups["price"].Value.Trim()}";
        }

        return string.Empty;
    }

    private static string FormatPriceDisplay(string? amountRaw, string? currencyRaw)
    {
        if (string.IsNullOrWhiteSpace(amountRaw))
        {
            return string.Empty;
        }

        var amount = NormalizeDecimal(amountRaw);
        if (!decimal.TryParse(amount, NumberStyles.Number, CultureInfo.InvariantCulture, out var value))
        {
            return string.Empty;
        }

        var currency = (currencyRaw ?? string.Empty).Trim().ToUpperInvariant();
        if (currency is "BRL" or "R$")
        {
            return $"R$ {value.ToString("N2", CultureInfo.GetCultureInfo("pt-BR"))}";
        }

        if (string.IsNullOrWhiteSpace(currency))
        {
            if (value < 5)
            {
                return string.Empty;
            }
            return value.ToString("N2", CultureInfo.GetCultureInfo("pt-BR"));
        }

        return $"{currency} {value.ToString("0.00", CultureInfo.InvariantCulture)}";
    }

    private static string NormalizeDecimal(string raw)
    {
        var value = (raw ?? string.Empty).Trim();
        value = Regex.Replace(value, @"[^\d\.,]", string.Empty, RegexOptions.CultureInvariant);
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var hasComma = value.Contains(',', StringComparison.Ordinal);
        var hasDot = value.Contains('.', StringComparison.Ordinal);
        if (hasComma && hasDot)
        {
            var lastComma = value.LastIndexOf(',');
            var lastDot = value.LastIndexOf('.');
            if (lastComma > lastDot)
            {
                value = value.Replace(".", string.Empty, StringComparison.Ordinal).Replace(",", ".", StringComparison.Ordinal);
            }
            else
            {
                value = value.Replace(",", string.Empty, StringComparison.Ordinal);
            }
        }
        else if (hasComma)
        {
            value = value.Replace(",", ".", StringComparison.Ordinal);
        }

        return value;
    }

    private record CacheEntry(DateTimeOffset Timestamp, LinkMetaResult Result);
}

public sealed class LinkMetaResult
{
    public string? Title { get; set; }
    public string? Description { get; set; }
    public string? PriceText { get; set; }
    public string? PreviousPriceText { get; set; }
    public int? DiscountPercentFromHtml { get; set; }
    public string? ResolvedUrl { get; set; }
    public List<string> Images { get; set; } = new();
    public List<string> Videos { get; set; } = new();
}
