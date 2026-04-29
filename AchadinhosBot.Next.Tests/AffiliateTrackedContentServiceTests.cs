using System.Net.Http;
using Microsoft.Extensions.Logging.Abstractions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public sealed class AffiliateTrackedContentServiceTests
{
    [Fact]
    public async Task RewriteAsync_ShouldConvertShopeeBeforeTracking_ForWhatsApp()
    {
        var trackingStore = new RecordingLinkTrackingStore();
        var trackingService = new TrackingLinkShortenerService(
            trackingStore,
            new FakeHttpClientFactory(),
            new FakeSettingsStore(),
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://reidasofertas.ia.br" }),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<TrackingLinkShortenerService>.Instance);

        var service = new AffiliateTrackedContentService(
            new FakeAffiliateLinkService("https://s.shopee.com.br/LjAwdaCJu?lp=aff", "Shopee"),
            trackingService,
            NullLogger<AffiliateTrackedContentService>.Instance);

        var result = await service.RewriteAsync(
            "Oferta teste https://s.shopee.com.br/AUpvSsCTgY",
            "whatsapp_dm",
            CancellationToken.None);

        Assert.Equal("Oferta teste https://reidasofertas.ia.br/r/SP-000001", result);
        Assert.Equal("https://s.shopee.com.br/LjAwdaCJu?lp=aff", trackingStore.LastTargetUrl);
        Assert.Equal("Shopee", trackingStore.LastStore);
    }

    [Fact]
    public async Task RewriteAsync_ShouldKeepOperationalLinksUntouched()
    {
        var trackingService = new TrackingLinkShortenerService(
            new RecordingLinkTrackingStore(),
            new FakeHttpClientFactory(),
            new FakeSettingsStore(),
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://reidasofertas.ia.br" }),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<TrackingLinkShortenerService>.Instance);

        var service = new AffiliateTrackedContentService(
            new FakeAffiliateLinkService("https://s.shopee.com.br/LjAwdaCJu?lp=aff", "Shopee"),
            trackingService,
            NullLogger<AffiliateTrackedContentService>.Instance);

        var result = await service.RewriteAsync(
            "Footer https://reidasofertas.ia.br/bio",
            "whatsapp_grupo",
            CancellationToken.None);

        Assert.Equal("Footer https://reidasofertas.ia.br/bio", result);
    }

    [Fact]
    public async Task RewriteAsync_ShouldKeepOfficialBioSubdomainUntouched()
    {
        var trackingService = new TrackingLinkShortenerService(
            new RecordingLinkTrackingStore(),
            new FakeHttpClientFactory(),
            new FakeSettingsStore(),
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://reidasofertas.ia.br" }),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<TrackingLinkShortenerService>.Instance);

        var service = new AffiliateTrackedContentService(
            new FakeAffiliateLinkService("https://s.shopee.com.br/LjAwdaCJu?lp=aff", "Shopee"),
            trackingService,
            NullLogger<AffiliateTrackedContentService>.Instance);

        var result = await service.RewriteAsync(
            "Footer https://bio.reidasofertas.ia.br",
            "whatsapp_grupo",
            CancellationToken.None);

        Assert.Equal("Footer https://bio.reidasofertas.ia.br", result);
    }

    private sealed class FakeAffiliateLinkService : IAffiliateLinkService
    {
        private readonly string _convertedUrl;
        private readonly string _store;

        public FakeAffiliateLinkService(string convertedUrl, string store)
        {
            _convertedUrl = convertedUrl;
            _store = store;
        }

        public Task<AffiliateLinkResult> ConvertAsync(string rawUrl, CancellationToken cancellationToken, string? source = null, bool forceResolution = false)
        {
            if (rawUrl.Contains("shopee", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new AffiliateLinkResult(true, _convertedUrl, _store, true, null, null, false, null));
            }

            return Task.FromResult(new AffiliateLinkResult(false, null, "Unknown", false, null, "not-converted", false, null));
        }
    }

    private sealed class RecordingLinkTrackingStore : ILinkTrackingStore
    {
        public string? LastTargetUrl { get; private set; }
        public string? LastStore { get; private set; }

        public Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry> GetOrCreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
        {
            LastTargetUrl = request.TargetUrl;
            LastStore = request.Store;
            var prefix = string.Equals(request.Store, "Shopee", StringComparison.OrdinalIgnoreCase) ? "SP" : "LK";
            return Task.FromResult(new LinkTrackingEntry
            {
                Id = $"{prefix}-000001",
                Slug = $"{prefix}-000001",
                TargetUrl = request.TargetUrl,
                Store = request.Store ?? string.Empty,
                OriginChannel = request.OriginChannel ?? "unknown",
                OriginSurface = request.OriginSurface ?? "unknown"
            });
        }

        public Task<LinkTrackingEntry> GetOrCreateAsync(string targetUrl, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry?> RegisterClickAsync(string trackingId, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry?> GetLinkAsync(string id, CancellationToken cancellationToken)
            => Task.FromResult<LinkTrackingEntry?>(null);

        public Task<IReadOnlyList<LinkTrackingEntry>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<LinkTrackingEntry>>(Array.Empty<LinkTrackingEntry>());
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new StubHandler());
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.AbsolutePath.Contains("/r/", StringComparison.OrdinalIgnoreCase) == true)
            {
                var response = new HttpResponseMessage(System.Net.HttpStatusCode.Found)
                {
                    Headers = { Location = new Uri("https://s.shopee.com.br/LjAwdaCJu?lp=aff") }
                };

                return Task.FromResult(response);
            }

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    private sealed class FakeSettingsStore : ISettingsStore
    {
        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken)
            => Task.FromResult(new AutomationSettings
            {
                BioHub = new BioHubSettings
                {
                    PublicBaseUrl = "https://reidasofertas.ia.br"
                }
            });

        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }
}
