using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Endpoints;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class LogsReadEndpointsContractTests
{
    [Fact]
    public async Task ConversionLogs_RequireReadAccessAndPreserveQueryDefaults()
    {
        await using var host = await LogsReadEndpointHost.CreateAsync();

        var anonymous = await host.Client.GetAsync("/api/logs/conversions");
        var operatorRequest = new HttpRequestMessage(HttpMethod.Get, "/api/logs/conversions?store=amazon&q=mouse&limit=25");
        operatorRequest.Headers.Add("X-Test-Role", "operator");
        var authorized = await host.Client.SendAsync(operatorRequest);

        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
        Assert.Equal("amazon", host.ConversionStore.LastQuery!.Store);
        Assert.Equal("mouse", host.ConversionStore.LastQuery.Search);
        Assert.Equal(25, host.ConversionStore.LastQuery.Limit);
    }

    private sealed class LogsReadEndpointHost : IAsyncDisposable
    {
        private readonly WebApplication _app;

        private LogsReadEndpointHost(WebApplication app, HttpClient client, TestConversionLogStore conversionStore)
        {
            _app = app;
            Client = client;
            ConversionStore = conversionStore;
        }

        internal HttpClient Client { get; }
        internal TestConversionLogStore ConversionStore { get; }

        internal static async Task<LogsReadEndpointHost> CreateAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddAuthentication(TestAuthenticationHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestAuthenticationHandler.SchemeName, _ => { });
            builder.Services.AddAuthorization(options =>
                options.AddPolicy("ReadAccess", policy => policy.RequireRole("admin", "operator")));

            var conversionStore = new TestConversionLogStore();
            builder.Services.AddSingleton<IConversionLogStore>(conversionStore);
            builder.Services.AddSingleton<IClickLogStore, EmptyClickLogStore>();
            builder.Services.AddSingleton<IInstagramAiLogStore, EmptyInstagramAiLogStore>();
            builder.Services.AddSingleton<IInstagramPublishLogStore, EmptyInstagramPublishLogStore>();
            builder.Services.AddSingleton<IMediaFailureLogStore, EmptyMediaFailureLogStore>();
            builder.Services.AddSingleton<IOfficialWhatsAppBlockedOfferStore, EmptyOfficialWhatsAppBlockedOfferStore>();

            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapGroup("/api").RequireAuthorization("ReadAccess").MapLogsReadEndpoints();
            await app.StartAsync();

            return new LogsReadEndpointHost(app, app.GetTestClient(), conversionStore);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    private sealed class TestAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        internal const string SchemeName = "LogsReadEndpointTest";

        public TestAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var role = Request.Headers["X-Test-Role"].SingleOrDefault();
            if (string.IsNullOrWhiteSpace(role))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Role, role)], SchemeName);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }

    private sealed class TestConversionLogStore : IConversionLogStore
    {
        internal ConversionLogQuery? LastQuery { get; private set; }

        public Task AppendAsync(ConversionLogEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<ConversionLogEntry>> QueryAsync(ConversionLogQuery query, CancellationToken cancellationToken)
        {
            LastQuery = query;
            return Task.FromResult<IReadOnlyList<ConversionLogEntry>>([]);
        }

        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class EmptyClickLogStore : IClickLogStore
    {
        public Task AppendAsync(ClickLogEntry entry, string? category, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<ClickLogEntry>> QueryAsync(string? category, string? search, int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ClickLogEntry>>([]);
        public Task ClearAsync(string? category, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class EmptyInstagramAiLogStore : IInstagramAiLogStore
    {
        public Task AppendAsync(InstagramAiLogEntry entry, CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<InstagramAiLogEntry>> ListAsync(int take, CancellationToken ct) => Task.FromResult<IReadOnlyList<InstagramAiLogEntry>>([]);
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class EmptyInstagramPublishLogStore : IInstagramPublishLogStore
    {
        public Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct) => Task.FromResult<IReadOnlyList<InstagramPublishLogEntry>>([]);
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class EmptyMediaFailureLogStore : IMediaFailureLogStore
    {
        public Task AppendAsync(MediaFailureEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<MediaFailureEntry>> ListAsync(int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MediaFailureEntry>>([]);
        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class EmptyOfficialWhatsAppBlockedOfferStore : IOfficialWhatsAppBlockedOfferStore
    {
        public Task AppendAsync(OfficialWhatsAppBlockedOfferEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<OfficialWhatsAppBlockedOfferEntry>> ListAsync(int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<OfficialWhatsAppBlockedOfferEntry>>([]);
        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
