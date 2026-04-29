using System.Net.Http;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppPublishContentServiceTests
{
    [Fact]
    public async Task PrepareAsync_ShouldUseMessageProcessorAndTracking_WhenProcessorConverts()
    {
        var trackingStore = new RecordingLinkTrackingStore();
        var trackingService = CreateTrackingService(trackingStore);
        var service = new WhatsAppPublishContentService(
            new FakeMessageProcessor(new ConversionResult(
                true,
                "Oferta pronta\n\nComparativo\nhttps://www.amazon.com.br/dp/B0CYJ7DBQC?tag=reidasofer022-20",
                1,
                "WhatsAppAdmin")),
            CreateAffiliateFallbackService(trackingStore),
            trackingService,
            new FakeOfferImageResolver(OfferImageResolutionResult.Failure("no_image_found")),
            new FakeSettingsStore(),
            Options.Create(new DeliverySafetyOptions()),
            NullLogger<WhatsAppPublishContentService>.Instance);

        var result = await service.PrepareAsync("https://www.amazon.com.br/dp/B0CYJ7DBQC", "5513992016907@s.whatsapp.net", CancellationToken.None);

        Assert.Contains("Oferta pronta\n\nComparativo\nhttps://reidasofertas.ia.br/r/AM-", result);
        Assert.Equal("https://www.amazon.com.br/dp/B0CYJ7DBQC?tag=reidasofer022-20", trackingStore.LastTargetUrl);
        Assert.Equal("whatsapp_dm", trackingStore.LastOriginSurface);
    }

    [Fact]
    public async Task PrepareAsync_ShouldFallbackToAffiliateTracking_WhenProcessorDoesNotConvert()
    {
        var trackingStore = new RecordingLinkTrackingStore();
        var service = new WhatsAppPublishContentService(
            new FakeMessageProcessor(new ConversionResult(false, null, 0, "WhatsAppAdmin")),
            CreateAffiliateFallbackService(trackingStore),
            CreateTrackingService(trackingStore),
            new FakeOfferImageResolver(OfferImageResolutionResult.Failure("no_image_found")),
            new FakeSettingsStore(),
            Options.Create(new DeliverySafetyOptions()),
            NullLogger<WhatsAppPublishContentService>.Instance);

        var result = await service.PrepareAsync("Oferta https://tinyurl.com/exemplo", "120363405661434395@g.us", CancellationToken.None);

        Assert.Contains("Oferta https://reidasofertas.ia.br/r/AM-", result);
        Assert.Equal("https://www.amazon.com.br/dp/B0CYJ7DBQC?tag=reidasofer022-20", trackingStore.LastTargetUrl);
        Assert.Equal("whatsapp_grupo", trackingStore.LastOriginSurface);
    }

    [Fact]
    public async Task PrepareAsync_ShouldReturnOriginalText_WhenThereIsNoUrl()
    {
        var trackingStore = new RecordingLinkTrackingStore();
        var service = new WhatsAppPublishContentService(
            new FakeMessageProcessor(new ConversionResult(true, "ignored", 1, "WhatsAppAdmin")),
            CreateAffiliateFallbackService(trackingStore),
            CreateTrackingService(trackingStore),
            new FakeOfferImageResolver(OfferImageResolutionResult.Failure("no_image_found")),
            new FakeSettingsStore(),
            Options.Create(new DeliverySafetyOptions()),
            NullLogger<WhatsAppPublishContentService>.Instance);

        var result = await service.PrepareAsync("Mensagem sem link", "5513992016907@s.whatsapp.net", CancellationToken.None);

        Assert.Equal("Mensagem sem link", result);
        Assert.Null(trackingStore.LastTargetUrl);
    }

    [Fact]
    public async Task PrepareForSendAsync_ShouldResolveImage_WhenTextHasTrackedOffer()
    {
        var trackingStore = new RecordingLinkTrackingStore();
        var service = new WhatsAppPublishContentService(
            new FakeMessageProcessor(new ConversionResult(
                true,
                "Oferta pronta\nhttps://www.amazon.com.br/dp/B0CYJ7DBQC?tag=reidasofer022-20",
                1,
                "WhatsAppAdmin")),
            CreateAffiliateFallbackService(trackingStore),
            CreateTrackingService(trackingStore),
            new FakeOfferImageResolver(OfferImageResolutionResult.SuccessFromBytes(new byte[] { 1, 2, 3, 4, 5, 6 }, "image/jpeg", "resolver")),
            new FakeSettingsStore(),
            Options.Create(new DeliverySafetyOptions()),
            NullLogger<WhatsAppPublishContentService>.Instance);

        var prepared = await service.PrepareForSendAsync(
            "https://www.amazon.com.br/dp/B0CYJ7DBQC",
            null,
            "120363405661434395@g.us",
            CancellationToken.None);

        Assert.Contains("Oferta pronta\nhttps://reidasofertas.ia.br/r/AM-", prepared.Content);
        Assert.True(prepared.HasImageCandidate);
        Assert.NotNull(prepared.ResolvedImageBytes);
        Assert.Equal("image/jpeg", prepared.ResolvedMimeType);
    }

    [Fact]
    public async Task PrepareAsync_ShouldMarkOfficialGroupSurface_WhenDestinationMatchesOfficialGroup()
    {
        var trackingStore = new RecordingLinkTrackingStore();
        var trackingService = CreateTrackingService(trackingStore);
        var service = new WhatsAppPublishContentService(
            new FakeMessageProcessor(new ConversionResult(
                true,
                "Oferta pronta\n\nComparativo\nhttps://www.amazon.com.br/dp/B0CYJ7DBQC?tag=reidasofer022-20",
                1,
                "WhatsAppAdmin")),
            CreateAffiliateFallbackService(trackingStore),
            trackingService,
            new FakeOfferImageResolver(OfferImageResolutionResult.Failure("no_image_found")),
            new FakeSettingsStore(),
            Options.Create(new DeliverySafetyOptions
            {
                OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
            }),
            NullLogger<WhatsAppPublishContentService>.Instance);

        var result = await service.PrepareAsync("https://www.amazon.com.br/dp/B0CYJ7DBQC", "120363405661434395@g.us", CancellationToken.None);

        Assert.Contains("Oferta pronta\n\nComparativo\nhttps://reidasofertas.ia.br/r/AM-", result);
        Assert.Contains("?src=whatsapp_grupo_oficial", result);
        Assert.Equal("whatsapp_grupo_oficial", trackingStore.LastOriginSurface);
    }

    [Fact]
    public async Task PrepareAsync_ShouldAppendFooter_AndKeepTracking_ForOfficialGroup()
    {
        var trackingStore = new RecordingLinkTrackingStore();
        var trackingService = CreateTrackingService(trackingStore);
        var service = new WhatsAppPublishContentService(
            new FakeMessageProcessor(new ConversionResult(
                true,
                "Oferta pronta\n\nComparativo\nhttps://www.amazon.com.br/dp/B0CYJ7DBQC?tag=reidasofer022-20",
                1,
                "WhatsAppAdmin")),
            CreateAffiliateFallbackService(trackingStore),
            trackingService,
            new FakeOfferImageResolver(OfferImageResolutionResult.Failure("no_image_found")),
            new FakeSettingsStore("Rodape oficial do WhatsApp"),
            Options.Create(new DeliverySafetyOptions
            {
                OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
            }),
            NullLogger<WhatsAppPublishContentService>.Instance);

        var result = await service.PrepareAsync("https://www.amazon.com.br/dp/B0CYJ7DBQC", "120363405661434395@g.us", CancellationToken.None);

        Assert.Contains("https://reidasofertas.ia.br/r/AM-", result);
        Assert.Contains("?src=whatsapp_grupo_oficial", result);
        Assert.Contains("Rodape oficial do WhatsApp", result);
        Assert.Equal("whatsapp_grupo_oficial", trackingStore.LastOriginSurface);
    }

    private static TrackingLinkShortenerService CreateTrackingService(RecordingLinkTrackingStore trackingStore)
        => new(
            trackingStore,
            new FakeHttpClientFactory(),
            new FakeSettingsStore(),
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://reidasofertas.ia.br" }),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<TrackingLinkShortenerService>.Instance);

    private static AffiliateTrackedContentService CreateAffiliateFallbackService(RecordingLinkTrackingStore trackingStore)
        => new(
            new FakeAffiliateLinkService("https://www.amazon.com.br/dp/B0CYJ7DBQC?tag=reidasofer022-20", "Amazon"),
            CreateTrackingService(trackingStore),
            NullLogger<AffiliateTrackedContentService>.Instance);

    private sealed class FakeMessageProcessor : IMessageProcessor
    {
        private readonly ConversionResult _result;

        public FakeMessageProcessor(ConversionResult result)
        {
            _result = result;
        }

        public Task<ConversionResult> ProcessAsync(
            string input,
            string source,
            CancellationToken cancellationToken,
            long? originChatId = null,
            long? destinationChatId = null,
            string? originChatRef = null,
            string? destinationChatRef = null,
            string? sourceImageUrl = null)
            => Task.FromResult(_result);

        public Task<(string EnrichedText, string? ProductImageUrl, string? ProductVideoUrl)> EnrichTextWithProductDataAsync(
            string convertedText,
            string originalText,
            CancellationToken cancellationToken)
            => Task.FromResult((convertedText, (string?)null, (string?)null));
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
            => Task.FromResult(new AffiliateLinkResult(true, _convertedUrl, _store, true, null, null, false, null));
    }

    private sealed class RecordingLinkTrackingStore : ILinkTrackingStore
    {
        public string? LastTargetUrl { get; private set; }
        public string? LastOriginSurface { get; private set; }
        public int CreateCalls { get; private set; }

        public Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
        {
            CreateCalls += 1;
            LastTargetUrl = request.TargetUrl;
            LastOriginSurface = request.OriginSurface;
            var prefix = string.Equals(request.Store, "Amazon", StringComparison.OrdinalIgnoreCase) ? "AM" : "LK";
            return Task.FromResult(new LinkTrackingEntry
            {
                Id = $"{prefix}-{CreateCalls:000001}",
                Slug = $"{prefix}-{CreateCalls:000001}",
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
            var path = request.RequestUri?.AbsolutePath ?? string.Empty;
            if (path.Contains("/r/", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.Redirect));
            }

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    private sealed class FakeSettingsStore : ISettingsStore
    {
        private readonly string? _whatsAppFooter;

        public FakeSettingsStore(string? whatsAppFooter = null)
        {
            _whatsAppFooter = whatsAppFooter;
        }

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken)
            => Task.FromResult(new AutomationSettings
            {
                BioHub = new BioHubSettings
                {
                    PublicBaseUrl = "https://reidasofertas.ia.br"
                },
                WhatsAppForwarding = new WhatsAppForwardingSettings
                {
                    FooterText = _whatsAppFooter ?? string.Empty
                }
            });

        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class FakeOfferImageResolver : IOfferImageResolver
    {
        private readonly OfferImageResolutionResult _result;

        public FakeOfferImageResolver(OfferImageResolutionResult result)
        {
            _result = result;
        }

        public Task<OfferImageResolutionResult> ResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken)
            => Task.FromResult(_result);
    }
}
