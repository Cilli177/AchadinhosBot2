using System.Net;
using System.Net.Http;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Amazon;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class MercadoLivreFallbackTests
{
    [Fact]
    public async Task ConvertAsync_UsesLocalManualFallback_WithoutMercadoLivreApiCalls()
    {
        var handler = new StubHttpMessageHandler(request =>
        {
            if (request.RequestUri is not null &&
                request.RequestUri.Host.Contains("api.mercadolibre.com", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse(HttpStatusCode.InternalServerError, "{\"error\":\"ml_api_down\"}");
            }

            return JsonResponse(HttpStatusCode.NotFound, "{\"error\":\"unexpected\"}");
        });

        var service = CreateService(handler, requireOAuth: false);

        var result = await service.ConvertAsync(
            "https://produto.mercadolivre.com.br/MLB-123456789-item-teste",
            CancellationToken.None,
            source: "teste");

        Assert.True(result.Success);
        Assert.True(result.IsAffiliated);
        Assert.Equal("Mercado Livre", result.Store);
        Assert.NotNull(result.ConvertedUrl);
        Assert.Contains("https://produto.mercadolivre.com.br/MLB-123456789", result.ConvertedUrl!, StringComparison.Ordinal);
        Assert.Contains("matt_tool=tool123", result.ConvertedUrl!, StringComparison.Ordinal);
        Assert.Contains("matt_word=word456", result.ConvertedUrl!, StringComparison.Ordinal);
        Assert.DoesNotContain(handler.RequestedUrls, url => url.Contains("api.mercadolibre.com/items/MLB123456789", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(handler.RequestedUrls, url => url.Contains("api.mercadolibre.com/products/MLB123456789", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ConvertAsync_BlocksMercadoLivre_WhenNoReliableIdExists()
    {
        var handler = new StubHttpMessageHandler(request =>
        {
            if (request.RequestUri is not null &&
                request.RequestUri.Host.Contains("mercadolivre.com.br", StringComparison.OrdinalIgnoreCase))
            {
                return HtmlResponse(HttpStatusCode.OK, "<html><body>pagina sem item</body></html>");
            }

            return JsonResponse(HttpStatusCode.InternalServerError, "{\"error\":\"ml_api_down\"}");
        });

        var service = CreateService(handler, requireOAuth: false);

        var result = await service.ConvertAsync(
            "https://www.mercadolivre.com.br/ofertas/teste-sem-id",
            CancellationToken.None,
            source: "teste");

        Assert.False(result.Success);
        Assert.False(result.IsAffiliated);
        Assert.Equal("Mercado Livre", result.Store);
        Assert.Null(result.ConvertedUrl);
        Assert.NotNull(result.ValidationError);
        Assert.Contains("Produto", result.ValidationError!, StringComparison.Ordinal);
        Assert.Contains("identificado", result.ValidationError!, StringComparison.Ordinal);
    }

    private static AffiliateLinkService CreateService(StubHttpMessageHandler handler, bool requireOAuth)
    {
        var options = Options.Create(new AffiliateOptions
        {
            MercadoLivreMattTool = "tool123",
            MercadoLivreMattWord = "word456",
            MercadoLivreRequireOAuth = requireOAuth,
            LinkTagging = new AffiliateLinkTaggingOptions
            {
                Enabled = false
            }
        });

        var httpClientFactory = new StubHttpClientFactory(handler);
        var creator = new AmazonCreatorApiClient(options, httpClientFactory, NullLogger<AmazonCreatorApiClient>.Instance);
        var paApi = new AmazonPaApiClient(options, httpClientFactory, NullLogger<AmazonPaApiClient>.Instance);
        return new AffiliateLinkService(
            options,
            new FakeMercadoLivreOAuthService(),
            creator,
            paApi,
            NullLogger<AffiliateLinkService>.Instance,
            httpClientFactory);
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode statusCode, string body)
        => new(statusCode)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

    private static HttpResponseMessage HtmlResponse(HttpStatusCode statusCode, string body)
        => new(statusCode)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/html")
        };

    private sealed class FakeMercadoLivreOAuthService : IMercadoLivreOAuthService
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken)
            => Task.FromResult<string?>(null);

        public Task<MercadoLivreOAuthStatus> GetStatusAsync(CancellationToken cancellationToken)
            => Task.FromResult(new MercadoLivreOAuthStatus(
                Configured: false,
                Success: true,
                Message: "oauth nao exigido",
                UserId: null,
                Nickname: null,
                Email: null,
                AccessTokenExpiresAt: null,
                RefreshTokenRotated: false));

        public Task<MercadoLivreOAuthStatus> RefreshAndCheckAsync(CancellationToken cancellationToken)
            => GetStatusAsync(cancellationToken);
    }

    private sealed class StubHttpClientFactory(StubHttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public List<string> RequestedUrls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri is not null)
            {
                RequestedUrls.Add(request.RequestUri.ToString());
            }

            var response = responder(request);
            response.RequestMessage = request;
            return Task.FromResult(response);
        }
    }
}
