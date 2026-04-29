using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Infrastructure.ProductData;
using Microsoft.Extensions.Caching.Memory;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class OfferImageResolver : IOfferImageResolver
{
    private readonly Func<string, string?, CancellationToken, Task<OfficialProductDataResult?>> _officialLookup;
    private readonly IEnumerable<IStoreImageScraper> _storeImageScrapers;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OfferImageResolver> _logger;
    private readonly IMemoryCache _memoryCache;

    public OfferImageResolver(
        OfficialProductDataService officialProductDataService,
        IEnumerable<IStoreImageScraper> storeImageScrapers,
        IHttpClientFactory httpClientFactory,
        IMemoryCache memoryCache,
        ILogger<OfferImageResolver> logger)
        : this(officialProductDataService.TryGetBestAsync, storeImageScrapers, httpClientFactory, memoryCache, logger)
    {
    }

    internal OfferImageResolver(
        Func<string, string?, CancellationToken, Task<OfficialProductDataResult?>> officialLookup,
        IEnumerable<IStoreImageScraper> storeImageScrapers,
        IHttpClientFactory httpClientFactory,
        IMemoryCache memoryCache,
        ILogger<OfferImageResolver> logger)
    {
        _officialLookup = officialLookup;
        _storeImageScrapers = storeImageScrapers;
        _httpClientFactory = httpClientFactory;
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public async Task<OfferImageResolutionResult> ResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken)
    {
        var cacheKey = BuildCacheKey(request);
        if (_memoryCache.TryGetValue<OfferImageResolutionResult>(cacheKey, out var cached))
        {
            return cached;
        }

        var diagnostics = new List<string>();

        if (!string.IsNullOrWhiteSpace(request.PreferredImageUrl))
        {
            var preferred = await TryResolveFromDirectImageUrlAsync(request.PreferredImageUrl!, "enriched_product_image", diagnostics, cancellationToken);
            if (preferred.Success)
            {
                return CacheAndReturn(cacheKey, preferred);
            }
        }

        if (!string.IsNullOrWhiteSpace(request.OriginalUrl) || !string.IsNullOrWhiteSpace(request.ConvertedUrl))
        {
            try
            {
                var official = await _officialLookup(
                    request.OriginalUrl ?? request.ConvertedUrl ?? string.Empty,
                    request.ConvertedUrl,
                    cancellationToken);
                var officialImageUrl = official?.Images?.FirstOrDefault(static x => !string.IsNullOrWhiteSpace(x));
                if (!string.IsNullOrWhiteSpace(officialImageUrl))
                {
                    diagnostics.Add($"official={official!.DataSource}");
                    var officialResult = await TryResolveFromDirectImageUrlAsync(
                        officialImageUrl,
                        $"official_lookup:{official.DataSource}",
                        diagnostics,
                        cancellationToken,
                        official.Store);
                    if (officialResult.Success)
                    {
                        return CacheAndReturn(cacheKey, officialResult);
                    }
                }

                diagnostics.Add(official is null ? "official_lookup=miss" : "official_lookup=no_image");
            }
            catch (Exception ex)
            {
                diagnostics.Add("official_lookup=error");
                _logger.LogDebug(ex, "Falha no lookup oficial de imagem. original={OriginalUrl} converted={ConvertedUrl}", request.OriginalUrl, request.ConvertedUrl);
            }
        }

        var storeHint = NormalizeStoreKey(request.Store)
            ?? NormalizeStoreKey(TrackingLinkShortenerService.ResolveStoreHint(request.ConvertedUrl))
            ?? NormalizeStoreKey(TrackingLinkShortenerService.ResolveStoreHint(request.OriginalUrl));
        if (!string.IsNullOrWhiteSpace(storeHint))
        {
            var scraper = _storeImageScrapers.FirstOrDefault(x => string.Equals(x.Store, storeHint, StringComparison.OrdinalIgnoreCase));
            if (scraper is not null)
            {
                try
                {
                    var scraperResult = await scraper.TryResolveAsync(request, cancellationToken);
                    if (scraperResult?.Success == true)
                    {
                        return CacheAndReturn(cacheKey, scraperResult with
                        {
                            Diagnostics = diagnostics.Concat(scraperResult.Diagnostics).ToArray()
                        });
                    }

                    diagnostics.Add($"scraper_{storeHint}=miss");
                }
                catch (Exception ex)
                {
                    diagnostics.Add($"scraper_{storeHint}=error");
                    _logger.LogDebug(ex, "Falha no scraper de imagem. Store={Store} original={OriginalUrl} converted={ConvertedUrl}", storeHint, request.OriginalUrl, request.ConvertedUrl);
                }
            }
        }

        var genericUrls = new[] { request.ConvertedUrl, request.OriginalUrl }
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        foreach (var candidateUrl in genericUrls)
        {
            var generic = await TryResolveFromGenericMetadataAsync(candidateUrl, diagnostics, cancellationToken);
            if (generic.Success)
            {
                return CacheAndReturn(cacheKey, generic);
            }
        }

        diagnostics.Add("ai_fallback=skipped_no_provider");
        return CacheAndReturn(cacheKey, OfferImageResolutionResult.Failure("no_image_found", diagnostics, "resolver"));
    }

    private OfferImageResolutionResult CacheAndReturn(string cacheKey, OfferImageResolutionResult result)
    {
        var ttl = result.Success ? TimeSpan.FromMinutes(20) : TimeSpan.FromMinutes(5);
        _memoryCache.Set(cacheKey, result, ttl);
        return result;
    }

    private static string BuildCacheKey(OfferImageResolutionRequest request)
    {
        return string.Join("|",
            "offer-image",
            request.OriginalUrl?.Trim() ?? string.Empty,
            request.ConvertedUrl?.Trim() ?? string.Empty,
            request.Store?.Trim() ?? string.Empty,
            request.PreferredImageUrl?.Trim() ?? string.Empty);
    }

    private async Task<OfferImageResolutionResult> TryResolveFromGenericMetadataAsync(
        string pageUrl,
        List<string> diagnostics,
        CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var response = await client.GetAsync(pageUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                diagnostics.Add($"generic_metadata=http_{(int)response.StatusCode}");
                return OfferImageResolutionResult.Failure("generic_metadata_failed", diagnostics, "generic_metadata");
            }

            var html = await response.Content.ReadAsStringAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(html))
            {
                diagnostics.Add("generic_metadata=empty_html");
                return OfferImageResolutionResult.Failure("generic_metadata_failed", diagnostics, "generic_metadata");
            }

            var imageUrl = ExtractMetaImageUrl(html);
            if (string.IsNullOrWhiteSpace(imageUrl))
            {
                diagnostics.Add("generic_metadata=no_image");
                return OfferImageResolutionResult.Failure("generic_metadata_failed", diagnostics, "generic_metadata");
            }

            diagnostics.Add("generic_metadata=meta_image");
            return await TryResolveFromDirectImageUrlAsync(imageUrl, "generic_metadata", diagnostics, cancellationToken);
        }
        catch (Exception ex)
        {
            diagnostics.Add("generic_metadata=error");
            _logger.LogDebug(ex, "Falha ao resolver imagem por metadata. url={Url}", pageUrl);
            return OfferImageResolutionResult.Failure("generic_metadata_failed", diagnostics, "generic_metadata");
        }
    }

    private async Task<OfferImageResolutionResult> TryResolveFromDirectImageUrlAsync(
        string imageUrl,
        string source,
        List<string> diagnostics,
        CancellationToken cancellationToken,
        string? store = null)
    {
        if (string.IsNullOrWhiteSpace(imageUrl) || !Uri.TryCreate(imageUrl, UriKind.Absolute, out var imageUri))
        {
            diagnostics.Add($"{source}=invalid_url");
            return OfferImageResolutionResult.Failure("invalid_image_url", diagnostics, source);
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, imageUri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/*"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                diagnostics.Add($"{source}=http_{(int)response.StatusCode}");
                return OfferImageResolutionResult.Failure("image_download_failed", diagnostics, source);
            }

            var contentType = response.Content.Headers.ContentType?.MediaType;
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            if (bytes.Length < 512)
            {
                diagnostics.Add($"{source}=tiny_payload");
                return OfferImageResolutionResult.Failure("image_download_failed", diagnostics, source);
            }

            var effectiveMimeType = !string.IsNullOrWhiteSpace(contentType) && contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase)
                ? contentType
                : GuessMimeType(bytes);

            if (string.IsNullOrWhiteSpace(effectiveMimeType) || !effectiveMimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                diagnostics.Add($"{source}=non_image_payload");
                return OfferImageResolutionResult.Failure("image_download_failed", diagnostics, source);
            }

            diagnostics.Add($"{source}=ok");
            return new OfferImageResolutionResult(
                true,
                store is not null && string.Equals(store, "Shopee", StringComparison.OrdinalIgnoreCase) ? imageUri.ToString() : null,
                bytes,
                effectiveMimeType,
                source,
                null,
                diagnostics.ToArray());
        }
        catch (Exception ex)
        {
            diagnostics.Add($"{source}=error");
            _logger.LogDebug(ex, "Falha ao baixar imagem direta. source={Source} url={Url}", source, imageUrl);
            return OfferImageResolutionResult.Failure("image_download_failed", diagnostics, source);
        }
    }

    private static string? ExtractMetaImageUrl(string html)
    {
        var match = MetaImageRegex().Match(html);
        if (match.Success)
        {
            return WebUtility.HtmlDecode(match.Groups["url"].Value).Trim();
        }

        match = MetaImageReverseRegex().Match(html);
        if (match.Success)
        {
            return WebUtility.HtmlDecode(match.Groups["url"].Value).Trim();
        }

        return null;
    }

    private static string? NormalizeStoreKey(string? store)
    {
        if (string.IsNullOrWhiteSpace(store))
        {
            return null;
        }

        return store.Trim().ToLowerInvariant() switch
        {
            "amazon" => "Amazon",
            "mercado livre" => "Mercado Livre",
            "mercadolivre" => "Mercado Livre",
            "shopee" => "Shopee",
            _ => null
        };
    }

    private static string? GuessMimeType(byte[] bytes)
    {
        if (bytes.Length >= 8 &&
            bytes[0] == 0x89 &&
            bytes[1] == 0x50 &&
            bytes[2] == 0x4E &&
            bytes[3] == 0x47)
        {
            return "image/png";
        }

        if (bytes.Length >= 3 &&
            bytes[0] == 0xFF &&
            bytes[1] == 0xD8 &&
            bytes[2] == 0xFF)
        {
            return "image/jpeg";
        }

        if (bytes.Length >= 12 &&
            bytes[0] == 0x52 &&
            bytes[1] == 0x49 &&
            bytes[2] == 0x46 &&
            bytes[3] == 0x46 &&
            bytes[8] == 0x57 &&
            bytes[9] == 0x45 &&
            bytes[10] == 0x42 &&
            bytes[11] == 0x50)
        {
            return "image/webp";
        }

        return null;
    }

    [GeneratedRegex(@"<meta\s+property=""og:image""\s+content=""(?<url>[^""]+)""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MetaImageRegex();

    [GeneratedRegex(@"<meta\s+content=""(?<url>[^""]+)""\s+property=""og:image""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MetaImageReverseRegex();
}
