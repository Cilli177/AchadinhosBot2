using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Amazon;

public sealed partial class AmazonStoreImageScraper : IStoreImageScraper
{
    private readonly AmazonPlaywrightScraperClient _amazonPlaywrightScraperClient;

    public AmazonStoreImageScraper(AmazonPlaywrightScraperClient amazonPlaywrightScraperClient)
    {
        _amazonPlaywrightScraperClient = amazonPlaywrightScraperClient;
    }

    public string Store => "Amazon";

    public async Task<OfferImageResolutionResult?> TryResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken)
    {
        var asin = ExtractAsin(request.ConvertedUrl) ?? ExtractAsin(request.OriginalUrl);
        if (string.IsNullOrWhiteSpace(asin))
        {
            return OfferImageResolutionResult.Failure("store_scraper_failed", new[] { "amazon_scraper=no_asin" }, "amazon_scraper");
        }

        var scraped = await _amazonPlaywrightScraperClient.ScrapeAsync(asin, cancellationToken);
        var imageUrl = scraped?.Images?.FirstOrDefault(static x => !string.IsNullOrWhiteSpace(x));
        if (string.IsNullOrWhiteSpace(imageUrl))
        {
            return OfferImageResolutionResult.Failure("store_scraper_failed", new[] { "amazon_scraper=no_image" }, "amazon_scraper");
        }

        return OfferImageResolutionResult.SuccessFromUrl(imageUrl, "amazon_scraper", new[] { "amazon_scraper=ok" });
    }

    private static string? ExtractAsin(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var match = AsinRegex().Match(url);
        return match.Success ? match.Groups["asin"].Value : null;
    }

    [GeneratedRegex(@"(?:/dp/|/gp/product/|/product/)(?<asin>[A-Z0-9]{10})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AsinRegex();
}
