using System.Net;
using AchadinhosBot.Next.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;

namespace AchadinhosBot.Next.Tests;

public sealed class InternalWebhookBoundaryContractTests
{
    [Fact]
    public async Task WebRuntime_HidesTheInternalWebhookBeforeRouting()
    {
        await using var host = await Host.CreateAsync(isWorkerRole: false);

        var response = await host.Client.PostAsync(InternalWebhookBoundaryExtensions.BotConversorPath, new StringContent("{}"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task WorkerRuntime_AllowsTheInternalWebhookToReachItsRoute()
    {
        await using var host = await Host.CreateAsync(isWorkerRole: true);

        var response = await host.Client.PostAsync(InternalWebhookBoundaryExtensions.BotConversorPath, new StringContent("{}"));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public void AccessPolicy_AllowsLoopbackWithoutAWebhookCredential()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Loopback;

        var allowed = InternalWebhookBoundaryExtensions.IsInternalBotConversorRequestAuthorized(context.Request, "{}", null, null);

        Assert.True(allowed);
    }

    [Fact]
    public void AccessPolicy_RequiresCredentialForANonLoopbackCaller()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("10.10.10.10");

        var denied = InternalWebhookBoundaryExtensions.IsInternalBotConversorRequestAuthorized(context.Request, "{}", null, "api-key");
        context.Request.Headers["x-api-key"] = "api-key";
        var allowed = InternalWebhookBoundaryExtensions.IsInternalBotConversorRequestAuthorized(context.Request, "{}", null, "api-key");

        Assert.False(denied);
        Assert.True(allowed);
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        internal HttpClient Client { get; }

        private Host(WebApplication app, HttpClient client) { _app = app; Client = client; }

        internal static async Task<Host> CreateAsync(bool isWorkerRole)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            var app = builder.Build();
            app.UseInternalWebhookExposureGuard(isWorkerRole);
            app.MapPost(InternalWebhookBoundaryExtensions.BotConversorPath, () => Results.NoContent());
            await app.StartAsync();
            return new Host(app, app.GetTestClient());
        }

        public async ValueTask DisposeAsync() { Client.Dispose(); await _app.StopAsync(); await _app.DisposeAsync(); }
    }
}
