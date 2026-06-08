using System.Net;
using System.Net.Http;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Infrastructure.ProductData;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class OfferImageResolverTests
{
    [Fact]
    public void NormalizeOfficialInviteBlock_ShouldReplaceLegacyInviteLink()
    {
        var input = """
            💚CONVIDEM MEMBROS
            LINK DOS GRUPOS: https://chat.whatsapp.com/LinkAntigo123
            """;

        var normalized = WhatsAppInviteLinkNormalizer.NormalizeOfficialInviteBlock(input);

        Assert.Contains(WhatsAppInviteLinkNormalizer.OfficialInviteUrl, normalized);
        Assert.DoesNotContain("LinkAntigo123", normalized);
    }

    [Theory]
    [InlineData("Para mais novidades, acesse: bio.reidasofertas.ia.br")]
    [InlineData("Para mais novidades, acesse: https://reidasofertas.ia.br/bio")]
    [InlineData("Para mais novidades, acesse: https://bio.reidasofertas.ia.br/bio")]
    public void NormalizeOfficialInviteBlock_ShouldCanonicalizeOfficialBioFooter(string input)
    {
        var normalized = WhatsAppInviteLinkNormalizer.NormalizeOfficialInviteBlock(input);

        Assert.Contains(WhatsAppInviteLinkNormalizer.OfficialBioUrl, normalized);
        Assert.DoesNotContain("https://reidasofertas.ia.br/bio", normalized);
        Assert.DoesNotContain("https://bio.reidasofertas.ia.br/bio", normalized);
    }

    [Fact]
    public async Task ResolveAsync_ShouldPreferPreferredImageUrl()
    {
        var resolver = CreateResolver(
            officialLookup: static (_, _, _) => Task.FromResult<OfficialProductDataResult?>(null),
            httpHandler: new StubHttpMessageHandler((request, _) =>
            {
                if (request.RequestUri!.AbsoluteUri == "https://cdn.test/preferred.jpg")
                {
                    return Task.FromResult(CreateImageResponse("image/jpeg", CreateJpegBytes()));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }));

        var result = await resolver.ResolveAsync(
            new OfferImageResolutionRequest(null, null, "Oferta", "Amazon", "https://cdn.test/preferred.jpg"),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("enriched_product_image", result.Source);
        Assert.Equal("image/jpeg", result.MimeType);
        Assert.NotNull(result.ResolvedImageBytes);
    }

    [Fact]
    public async Task ResolveAsync_ShouldUseOfficialLookupBeforeStoreScraper()
    {
        var scraperCalls = 0;
        var resolver = CreateResolver(
            officialLookup: static (_, _, _) => Task.FromResult<OfficialProductDataResult?>(
                new OfficialProductDataResult(
                    "Shopee",
                    "Produto",
                    "R$ 10,00",
                    null,
                    10,
                    new List<string> { "https://cdn.test/official.webp" },
                    true,
                    "shopee_affiliate_graphql",
                    "https://s.shopee.com.br/oferta",
                    null,
                    null)),
            scrapers: new[]
            {
                new FakeStoreImageScraper("Shopee", _ =>
                {
                    scraperCalls++;
                    return Task.FromResult<OfferImageResolutionResult?>(OfferImageResolutionResult.SuccessFromBytes(CreatePngBytes(), "image/png", "scraper"));
                })
            },
            httpHandler: new StubHttpMessageHandler((request, _) =>
            {
                if (request.RequestUri!.AbsoluteUri == "https://cdn.test/official.webp")
                {
                    return Task.FromResult(CreateImageResponse("image/webp", CreateWebpBytes()));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }));

        var result = await resolver.ResolveAsync(
            new OfferImageResolutionRequest("https://s.shopee.com.br/abc", "https://s.shopee.com.br/xyz", "Oferta", "Shopee", null),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.StartsWith("official_lookup:", result.Source, StringComparison.Ordinal);
        Assert.Equal(0, scraperCalls);
    }

    [Fact]
    public async Task ResolveAsync_ShouldFallbackToStoreScraperWhenOfficialMisses()
    {
        var resolver = CreateResolver(
            officialLookup: static (_, _, _) => Task.FromResult<OfficialProductDataResult?>(null),
            scrapers: new[]
            {
                new FakeStoreImageScraper("Mercado Livre", _ =>
                    Task.FromResult<OfferImageResolutionResult?>(
                        OfferImageResolutionResult.SuccessFromBytes(CreatePngBytes(), "image/png", "mercadolivre_scraper")))
            });

        var result = await resolver.ResolveAsync(
            new OfferImageResolutionRequest(null, null, "Oferta", "Mercado Livre", null),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("mercadolivre_scraper", result.Source);
        Assert.Equal("image/png", result.MimeType);
    }

    private static OfferImageResolver CreateResolver(
        Func<string, string?, CancellationToken, Task<OfficialProductDataResult?>> officialLookup,
        IEnumerable<IStoreImageScraper>? scrapers = null,
        HttpMessageHandler? httpHandler = null)
    {
        return new OfferImageResolver(
            officialLookup,
            scrapers ?? Array.Empty<IStoreImageScraper>(),
            new StubHttpClientFactory(httpHandler ?? new StubHttpMessageHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)))),
            new MemoryCache(new MemoryCacheOptions()),
            NullLogger<OfferImageResolver>.Instance);
    }

    private static HttpResponseMessage CreateImageResponse(string mimeType, byte[] bytes)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(bytes)
            {
                Headers =
                {
                    ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mimeType)
                }
            }
        };
    }

    private static byte[] CreateJpegBytes()
        => new byte[] { 0xFF, 0xD8, 0xFF }.Concat(Enumerable.Repeat((byte)0x01, 700)).ToArray();

    private static byte[] CreatePngBytes()
        => new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.Concat(Enumerable.Repeat((byte)0x02, 700)).ToArray();

    private static byte[] CreateWebpBytes()
    {
        var prefix = Encoding.ASCII.GetBytes("RIFF");
        var payload = Enumerable.Repeat((byte)0x03, 20).ToArray();
        var webp = Encoding.ASCII.GetBytes("WEBP");
        return prefix.Concat(payload.Take(4)).Concat(webp).Concat(payload).Concat(Enumerable.Repeat((byte)0x03, 700)).ToArray();
    }

    private sealed class FakeStoreImageScraper : IStoreImageScraper
    {
        private readonly Func<OfferImageResolutionRequest, Task<OfferImageResolutionResult?>> _callback;

        public FakeStoreImageScraper(string store, Func<OfferImageResolutionRequest, Task<OfferImageResolutionResult?>> callback)
        {
            Store = store;
            _callback = callback;
        }

        public string Store { get; }

        public Task<OfferImageResolutionResult?> TryResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken)
            => _callback(request);
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public StubHttpClientFactory(HttpMessageHandler handler)
        {
            _handler = handler;
        }

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _handler;

        public StubHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => _handler(request, cancellationToken);
    }
}
