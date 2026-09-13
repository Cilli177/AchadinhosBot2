using System.Net;
using AchadinhosBot.Next.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AchadinhosBot.Next.Tests;

public sealed class PublicMediaEndpointsContractTests
{
    [Fact]
    public async Task RemoteMedia_InvalidUrl_IsRejectedBeforeAnOutboundRequest()
    {
        await using var host = await Host.CreateAsync(_ => throw new InvalidOperationException("Outbound request was not expected."));

        var response = await host.Client.GetAsync("/media/remote?url=ftp%3A%2F%2Fexample.com%2Ffile.png");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RemoteMedia_ImageResponse_IsProxiedWithExistingCacheContract()
    {
        HttpRequestMessage? capturedRequest = null;
        await using var host = await Host.CreateAsync(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([1, 2, 3])
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("image/png") }
                }
            };
        });

        var response = await host.Client.GetAsync("/media/remote?url=https%3A%2F%2Fimages.example%2Foffer.png");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("image/png", response.Content.Headers.ContentType!.MediaType);
        Assert.True(response.Headers.CacheControl!.Public);
        Assert.Equal(TimeSpan.FromSeconds(1800), response.Headers.CacheControl.MaxAge);
        Assert.Equal([1, 2, 3], await response.Content.ReadAsByteArrayAsync());
        Assert.NotNull(capturedRequest);
        Assert.Equal("https://images.example/offer.png", capturedRequest.RequestUri!.ToString());
        Assert.Contains("ReiDasOfertasBot", capturedRequest.Headers.UserAgent.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RemoteMedia_NonImageResponse_IsRejected()
    {
        await using var host = await Host.CreateAsync(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not an image")
        });

        var response = await host.Client.GetAsync("/media/remote?url=https%3A%2F%2Fimages.example%2Foffer.txt");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        internal HttpClient Client { get; }

        private Host(WebApplication app, HttpClient client)
        {
            _app = app;
            Client = client;
        }

        internal static async Task<Host> CreateAsync(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton<IHttpClientFactory>(new StubHttpClientFactory(handler));
            var app = builder.Build();
            app.MapPublicMediaEndpoints();
            await app.StartAsync();
            return new Host(app, app.GetTestClient());
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(handler(request));
    }

    private sealed class StubHttpClientFactory(Func<HttpRequestMessage, HttpResponseMessage> handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new DelegateHandler(handler), disposeHandler: true);
    }
}
