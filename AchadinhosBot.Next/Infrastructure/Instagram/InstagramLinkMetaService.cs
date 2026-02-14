using System.Text.RegularExpressions;

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

            string? title = null;
            var ogTitle = Regex.Match(html, "<meta[^>]+property=[\"']og:title[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>", RegexOptions.IgnoreCase);
            if (ogTitle.Success && ogTitle.Groups.Count > 1)
            {
                title = ogTitle.Groups[1].Value;
            }
            if (string.IsNullOrWhiteSpace(title))
            {
                var titleTag = Regex.Match(html, "<title[^>]*>([^<]+)</title>", RegexOptions.IgnoreCase);
                if (titleTag.Success && titleTag.Groups.Count > 1)
                {
                    title = titleTag.Groups[1].Value;
                }
            }

            string? description = null;
            var ogDesc = Regex.Match(html, "<meta[^>]+property=[\"']og:description[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>", RegexOptions.IgnoreCase);
            if (ogDesc.Success && ogDesc.Groups.Count > 1)
            {
                description = ogDesc.Groups[1].Value;
            }
            if (string.IsNullOrWhiteSpace(description))
            {
                var metaDesc = Regex.Match(html, "<meta[^>]+name=[\"']description[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>", RegexOptions.IgnoreCase);
                if (metaDesc.Success && metaDesc.Groups.Count > 1)
                {
                    description = metaDesc.Groups[1].Value;
                }
            }

            var images = new List<string>();
            var ogMatches = Regex.Matches(html, "<meta[^>]+property=[\"']og:image[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>", RegexOptions.IgnoreCase);
            foreach (Match m in ogMatches)
            {
                if (m.Groups.Count > 1)
                {
                    var url = m.Groups[1].Value;
                    if (!string.IsNullOrWhiteSpace(url)) images.Add(url);
                }
            }

            var twMatches = Regex.Matches(html, "<meta[^>]+name=[\"']twitter:image[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>", RegexOptions.IgnoreCase);
            foreach (Match m in twMatches)
            {
                if (m.Groups.Count > 1)
                {
                    var url = m.Groups[1].Value;
                    if (!string.IsNullOrWhiteSpace(url)) images.Add(url);
                }
            }

            var result = new LinkMetaResult
            {
                Title = title?.Trim(),
                Description = description?.Trim(),
                Images = images.Distinct().Take(8).ToList()
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

    private record CacheEntry(DateTimeOffset Timestamp, LinkMetaResult Result);
}

public sealed class LinkMetaResult
{
    public string? Title { get; set; }
    public string? Description { get; set; }
    public List<string> Images { get; set; } = new();
}
