using System.Text.RegularExpressions;
using System.Net;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramLinkMetaService
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(20);
    private static readonly object CacheLock = new();
    private static readonly Dictionary<string, CacheEntry> Cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<InstagramLinkMetaService> _logger;

    public InstagramLinkMetaService(IHttpClientFactory httpClientFactory, ILogger<InstagramLinkMetaService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<LinkMetaResult> GetMetaAsync(string link, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(link)) return new LinkMetaResult();
        if (TryGetFromCache(link, out var cached)) return cached;

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var response = await client.GetAsync(link, ct);
            if (!response.IsSuccessStatusCode) return new LinkMetaResult();
            var html = await response.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(html)) return new LinkMetaResult();
            var resolvedUri = response.RequestMessage?.RequestUri;

            var title = FirstNonEmpty(
                ExtractMetaContent(html, "property", "og:title"),
                ExtractMetaContent(html, "name", "twitter:title"),
                ExtractTitleTag(html));

            var description = FirstNonEmpty(
                ExtractMetaContent(html, "property", "og:description"),
                ExtractMetaContent(html, "name", "description"),
                ExtractMetaContent(html, "name", "twitter:description"));

            var images = new List<string>();
            images.AddRange(ExtractMetaContents(html, "property", "og:image"));
            images.AddRange(ExtractMetaContents(html, "property", "og:image:url"));
            images.AddRange(ExtractMetaContents(html, "property", "og:image:secure_url"));
            images.AddRange(ExtractMetaContents(html, "name", "twitter:image"));
            images.AddRange(ExtractMetaContents(html, "name", "twitter:image:src"));
            images.AddRange(ExtractMetaContents(html, "itemprop", "image"));
            images.AddRange(ExtractLinkHrefs(html, "rel", "image_src"));
            images.AddRange(ExtractImageUrlsFromJsonLd(html));
            images.AddRange(ExtractImageUrlsFromImgTags(html));
            images = NormalizeImageUrls(images, resolvedUri);

            var result = new LinkMetaResult
            {
                Title = WebUtility.HtmlDecode(title?.Trim() ?? string.Empty),
                Description = WebUtility.HtmlDecode(description?.Trim() ?? string.Empty),
                Images = images
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
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
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
        if (path.EndsWith(".svg", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
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

    private record CacheEntry(DateTimeOffset Timestamp, LinkMetaResult Result);
}

public sealed class LinkMetaResult
{
    public string? Title { get; set; }
    public string? Description { get; set; }
    public List<string> Images { get; set; } = new();
}
