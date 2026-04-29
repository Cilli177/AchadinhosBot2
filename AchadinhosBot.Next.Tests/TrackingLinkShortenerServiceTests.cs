using System.Net.Http;
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

public sealed class TrackingLinkShortenerServiceTests
{
    [Fact]
    public async Task TrackSingleUrlAsync_ShouldOmitSrc_ForWhatsAppSurface()
    {
        var service = CreateService();

        var result = await service.TrackSingleUrlAsync(
            "https://www.amazon.com.br/dp/B08N5M7S6K",
            "whatsapp_grupo",
            CancellationToken.None,
            "Amazon");

        Assert.Equal("https://reidasofertas.ia.br/r/AM-000001", result);
    }

    [Fact]
    public async Task TrackSingleUrlAsync_ShouldKeepCompactSrc_ForWebSurface()
    {
        var service = CreateService();

        var result = await service.TrackSingleUrlAsync(
            "https://www.amazon.com.br/dp/B08N5M7S6K",
            "conversor_web",
            CancellationToken.None,
            "Amazon");

        Assert.Equal("https://reidasofertas.ia.br/r/AM-000001?src=cw", result);
    }

    [Fact]
    public async Task TrackSingleUrlAsync_ShouldNormalizeLegacyAchadinhosHost()
    {
        var service = CreateService(
            settingsPublicBaseUrl: "https://achadinhos.reidasofertas.ia.br",
            webhookPublicBaseUrl: "https://achadinhos.reidasofertas.ia.br");

        var result = await service.TrackSingleUrlAsync(
            "https://www.amazon.com.br/dp/B08N5M7S6K",
            "conversor_web",
            CancellationToken.None,
            "Amazon");

        Assert.Equal("https://reidasofertas.ia.br/r/AM-000001?src=cw", result);
    }

    [Fact]
    public async Task TrackSingleUrlAsync_ShouldFallbackToOriginalUrl_WhenTrackedUrlIsNotResolvable()
    {
        var service = CreateService(trackedUrlStatusCode: System.Net.HttpStatusCode.NotFound);

        var result = await service.TrackSingleUrlAsync(
            "https://www.amazon.com.br/dp/B08N5M7S6K",
            "conversor_web",
            CancellationToken.None,
            "Amazon");

        Assert.Equal("https://www.amazon.com.br/dp/B08N5M7S6K", result);
    }

    [Fact]
    public async Task TrackSingleUrlAsync_ShouldExpireTrackingLinksForAllSurfaces()
    {
        var trackingStore = new FakeLinkTrackingStore();
        var service = CreateService(trackingStore: trackingStore);

        var before = DateTimeOffset.UtcNow.AddDays(3);
        var result = await service.TrackSingleUrlAsync(
            "https://www.amazon.com.br/dp/B08N5M7S6K",
            "conversor_web",
            CancellationToken.None,
            "Amazon");
        var after = DateTimeOffset.UtcNow.AddDays(5);

        Assert.Equal("https://reidasofertas.ia.br/r/AM-000001?src=cw", result);
        Assert.NotNull(trackingStore.LastExpiresAtUtc);
        Assert.InRange(trackingStore.LastExpiresAtUtc!.Value, before, after);
    }

    [Fact]
    public async Task TrackSingleUrlAsync_ShouldCreateFreshTrackingIdOnRepeatedCalls()
    {
        var trackingStore = new FakeLinkTrackingStore();
        var service = CreateService(trackingStore: trackingStore);

        var first = await service.TrackSingleUrlAsync(
            "https://www.amazon.com.br/dp/B08N5M7S6K",
            "whatsapp_grupo_oficial",
            CancellationToken.None,
            "Amazon");
        var second = await service.TrackSingleUrlAsync(
            "https://www.amazon.com.br/dp/B08N5M7S6K",
            "whatsapp_grupo_oficial",
            CancellationToken.None,
            "Amazon");

        Assert.StartsWith("https://reidasofertas.ia.br/r/AM-", first);
        Assert.StartsWith("https://reidasofertas.ia.br/r/AM-", second);
        Assert.Contains("?src=whatsapp_grupo_oficial", first);
        Assert.Contains("?src=whatsapp_grupo_oficial", second);
        Assert.NotEqual(first, second);
        Assert.Equal(2, trackingStore.CreateCalls);
    }

    [Theory]
    [InlineData("https://www.amazon.com.br/dp/B08N5M7S6K", "Amazon", "https://reidasofertas.ia.br/r/AM-000001?src=cw")]
    [InlineData("https://www.mercadolivre.com.br/p/MLB19761624", "Mercado Livre", "https://reidasofertas.ia.br/r/ML-000001?src=cw")]
    [InlineData("https://s.shopee.com.br/AUpvSsCTgY", "Shopee", "https://reidasofertas.ia.br/r/SP-000001?src=cw")]
    public async Task TrackSingleUrlAsync_ShouldFollowCanonicalGoldenOutputs(string url, string store, string expected)
    {
        var service = CreateService();

        var result = await service.TrackSingleUrlAsync(
            url,
            "conversor_web",
            CancellationToken.None,
            store);

        Assert.Equal(expected, result);
    }

    private static TrackingLinkShortenerService CreateService(
        FakeLinkTrackingStore? trackingStore = null,
        string settingsPublicBaseUrl = "https://reidasofertas.ia.br",
        string webhookPublicBaseUrl = "https://reidasofertas.ia.br",
        System.Net.HttpStatusCode trackedUrlStatusCode = System.Net.HttpStatusCode.Redirect)
    {
        return new TrackingLinkShortenerService(
            trackingStore ?? new FakeLinkTrackingStore(),
            new FakeHttpClientFactory(trackedUrlStatusCode),
            new FakeSettingsStore(settingsPublicBaseUrl),
            Options.Create(new WebhookOptions { PublicBaseUrl = webhookPublicBaseUrl }),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<TrackingLinkShortenerService>.Instance);
    }

    private sealed class FakeLinkTrackingStore : ILinkTrackingStore
    {
        public DateTimeOffset? LastExpiresAtUtc { get; private set; }
        public int CreateCalls { get; private set; }

        public Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
        {
            CreateCalls += 1;
            LastExpiresAtUtc = request.ExpiresAtUtc;
            var prefix = ResolvePrefix(request.TargetUrl);
            return Task.FromResult(new LinkTrackingEntry
            {
                Id = $"{prefix}-{CreateCalls:000000}",
                Slug = $"{prefix}-{CreateCalls:000000}",
                TargetUrl = request.TargetUrl,
                Store = request.Store ?? string.Empty,
                OriginChannel = request.OriginChannel ?? "unknown",
                OriginSurface = request.OriginSurface ?? "unknown",
                ExpiresAtUtc = request.ExpiresAtUtc
            });
        }

        public Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken)
            => CreateAsync(new LinkTrackingCreateRequest { TargetUrl = targetUrl }, cancellationToken);

        public Task<LinkTrackingEntry> GetOrCreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
            => CreateAsync(request, cancellationToken);

        private static string ResolvePrefix(string? targetUrl)
        {
            if (!Uri.TryCreate(targetUrl ?? string.Empty, UriKind.Absolute, out var uri))
            {
                return "LK";
            }

            var host = uri.Host.ToLowerInvariant();
            if (host.Contains("amazon"))
            {
                return "AM";
            }

            if (host.Contains("mercadolivre") || host.Contains("mercadolibre") || host.Contains("meli."))
            {
                return "ML";
            }

            if (host.Contains("shopee"))
            {
                return "SP";
            }

            return "LK";
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
        private readonly System.Net.HttpStatusCode _trackedUrlStatusCode;

        public FakeHttpClientFactory(System.Net.HttpStatusCode trackedUrlStatusCode)
        {
            _trackedUrlStatusCode = trackedUrlStatusCode;
        }

        public HttpClient CreateClient(string name)
            => new(new StubHandler(_trackedUrlStatusCode));
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly System.Net.HttpStatusCode _trackedUrlStatusCode;

        public StubHandler(System.Net.HttpStatusCode trackedUrlStatusCode)
        {
            _trackedUrlStatusCode = trackedUrlStatusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.AbsolutePath ?? string.Empty;
            if (path.Contains("/r/", StringComparison.OrdinalIgnoreCase))
            {
                var response = new HttpResponseMessage(_trackedUrlStatusCode);
                if (_trackedUrlStatusCode is System.Net.HttpStatusCode.MovedPermanently or System.Net.HttpStatusCode.Found or System.Net.HttpStatusCode.Redirect)
                {
                    response.Headers.Location = new Uri("https://s.shopee.com.br/7VCfean7C9");
                }

                return Task.FromResult(response);
            }

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    private sealed class FakeSettingsStore : ISettingsStore
    {
        private readonly string _publicBaseUrl;

        public FakeSettingsStore(string publicBaseUrl)
        {
            _publicBaseUrl = publicBaseUrl;
        }

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken)
            => Task.FromResult(new AutomationSettings
            {
                BioHub = new BioHubSettings
                {
                    PublicBaseUrl = _publicBaseUrl
                }
            });

        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }
}
