using System.Net;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Amazon;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.ProductData;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Xunit.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class EnrichmentManualValidation
{
    private readonly ITestOutputHelper _output;

    public EnrichmentManualValidation(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact(Skip = "Temporarily ignored due to git reset")]
    public async Task TestPriceDetection_ShouldSkipEnrichment()
    {
        // Setup minimal dependencies
        var httpClient = new HttpClient();
        var clientFactory = new SimpleHttpClientFactory(httpClient);
        var affiliateOptions = Options.Create(new AffiliateOptions());
        var amazonPa = new AmazonPaApiClient(affiliateOptions, clientFactory, NullLogger<AmazonPaApiClient>.Instance);
        var amazonCreator = new AmazonCreatorApiClient(affiliateOptions, clientFactory, NullLogger<AmazonCreatorApiClient>.Instance);
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var amazonHtmlScraper = new AmazonHtmlScraperService(clientFactory, memoryCache, NullLogger<AmazonHtmlScraperService>.Instance);
        var scraper = new InstagramLinkMetaService(clientFactory, amazonPa, amazonHtmlScraper, NullLogger<InstagramLinkMetaService>.Instance);
        var m_meliAuth = new FakeMeliAuth();
        var official = new OfficialProductDataService(amazonPa, amazonCreator, amazonHtmlScraper, m_meliAuth, affiliateOptions, clientFactory, NullLogger<OfficialProductDataService>.Instance);
        
        var processor = new MessageProcessor(
            null!, null!, null!, null!, null!,
            official, NullLogger<MessageProcessor>.Instance);

        var originalText = "Oferta incrivel! Apenas R$ 199,90 no link: https://www.amazon.com.br/dp/B08P2CD4BY";
        var convertedText = "Oferta incrivel! Apenas R$ 199,90 no link: https://amzn.to/example";

        var (enriched, imageUrl, _) = await processor.EnrichTextWithProductDataAsync(convertedText, originalText, CancellationToken.None);

        _output.WriteLine($"Original: {originalText}");
        _output.WriteLine($"Enriched: {enriched}");

        Assert.Equal(convertedText, enriched); // Should be identical (no enrichment added)
        Assert.Null(imageUrl);
    }

    [Fact(Skip = "Temporarily ignored due to git reset")]
    public async Task TestScrapingFallback_RealCall()
    {
        // This test makes real calls to verify the fallback
        var httpClient = new HttpClient();
        var clientFactory = new SimpleHttpClientFactory(httpClient);
        var affiliateOptions = Options.Create(new AffiliateOptions());
        var amazonPa = new AmazonPaApiClient(affiliateOptions, clientFactory, NullLogger<AmazonPaApiClient>.Instance);
        var amazonCreator = new AmazonCreatorApiClient(affiliateOptions, clientFactory, NullLogger<AmazonCreatorApiClient>.Instance);
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var amazonHtmlScraper = new AmazonHtmlScraperService(clientFactory, memoryCache, NullLogger<AmazonHtmlScraperService>.Instance);
        var scraper = new InstagramLinkMetaService(clientFactory, amazonPa, amazonHtmlScraper, NullLogger<InstagramLinkMetaService>.Instance);
        var m_meliAuth = new FakeMeliAuth();
        var official = new OfficialProductDataService(amazonPa, amazonCreator, amazonHtmlScraper, m_meliAuth, affiliateOptions, clientFactory, NullLogger<OfficialProductDataService>.Instance);
        
        var processor = new MessageProcessor(
            null!, null!, null!, null!, null!,
            official, NullLogger<MessageProcessor>.Instance);

        // A URL that might not have official API data easily (or we can just check if fallback is triggered)
        // Using a Mercado Livre URL which often needs scraping for price if token is not valid
        var originalUrl = "https://www.mercadolivre.com.br/apple-iphone-15-128-gb-preto/p/MLB27633783";
        var originalText = $"Confira: {originalUrl}";
        var convertedText = $"Confira: https://mercadolivre.com/sec/example";

        _output.WriteLine($"Testing fallback for: {originalUrl}");
        var (enriched, imageUrl, _) = await processor.EnrichTextWithProductDataAsync(convertedText, originalText, CancellationToken.None);

        _output.WriteLine($"Enriched: {enriched}");
        _output.WriteLine($"Image: {imageUrl}");

        Assert.NotEqual(convertedText, enriched);
        Assert.True(enriched.Contains("💰") || enriched.Contains("🏷️"), "Enriched text should contain price or discount info.");
    }

    private sealed class SimpleHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SimpleHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class FakeMeliAuth : IMercadoLivreOAuthService
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task<MercadoLivreOAuthStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new MercadoLivreOAuthStatus(false, false, "Not configured", null, null, null, null, false));
        public Task<MercadoLivreOAuthStatus> RefreshAndCheckAsync(CancellationToken cancellationToken) => Task.FromResult(new MercadoLivreOAuthStatus(false, false, "Not configured", null, null, null, null, false));
    }
}
