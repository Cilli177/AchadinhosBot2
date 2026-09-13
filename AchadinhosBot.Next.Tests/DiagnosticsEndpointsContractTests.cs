using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Endpoints;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class DiagnosticsEndpointsContractTests
{
    [Fact]
    public async Task ApiDiagnostics_RequireReadAccessAndUseOAuthStatusWhenConfigured()
    {
        await using var host = await DiagnosticsEndpointHost.CreateAsync();

        var anonymous = await host.Client.GetAsync("/api/diagnostics/apis");
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/diagnostics/apis");
        request.Headers.Add("X-Test-Role", "operator");
        var authorized = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
        Assert.Equal(1, host.OAuth.StatusCalls);

        var body = await authorized.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("officialProductApis").GetProperty("mercadoLivre").GetProperty("oauthConfigured").GetBoolean());
        Assert.True(body.GetProperty("officialProductApis").GetProperty("mercadoLivre").GetProperty("oauthValid").GetBoolean());
        Assert.Equal("fake status", body.GetProperty("officialProductApis").GetProperty("mercadoLivre").GetProperty("oauthMessage").GetString());
    }

    private sealed class DiagnosticsEndpointHost : IAsyncDisposable
    {
        private readonly WebApplication _app;

        private DiagnosticsEndpointHost(WebApplication app, HttpClient client, FakeMercadoLivreOAuthService oauth)
        {
            _app = app;
            Client = client;
            OAuth = oauth;
        }

        internal HttpClient Client { get; }
        internal FakeMercadoLivreOAuthService OAuth { get; }

        internal static async Task<DiagnosticsEndpointHost> CreateAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddAuthentication(TestAuthenticationHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestAuthenticationHandler.SchemeName, _ => { });
            builder.Services.AddAuthorization(options =>
                options.AddPolicy("ReadAccess", policy => policy.RequireRole("admin", "operator")));
            builder.Services.AddSingleton<ISettingsStore, FakeSettingsStore>();
            builder.Services.AddSingleton<IOptions<AffiliateOptions>>(Options.Create(new AffiliateOptions
            {
                MercadoLivreClientId = "client",
                MercadoLivreClientSecret = "secret",
                MercadoLivreRefreshToken = "refresh",
                MercadoLivreUserId = "1"
            }));
            var oauth = new FakeMercadoLivreOAuthService();
            builder.Services.AddSingleton<IMercadoLivreOAuthService>(oauth);

            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapGroup("/api").RequireAuthorization("ReadAccess").MapDiagnosticsEndpoints();
            await app.StartAsync();

            return new DiagnosticsEndpointHost(app, app.GetTestClient(), oauth);
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
        internal const string SchemeName = "DiagnosticsEndpointTest";

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

    private sealed class FakeSettingsStore : ISettingsStore
    {
        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(new AutomationSettings());
        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FakeMercadoLivreOAuthService : IMercadoLivreOAuthService
    {
        internal int StatusCalls { get; private set; }

        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<MercadoLivreOAuthStatus> GetStatusAsync(CancellationToken cancellationToken)
        {
            StatusCalls++;
            return Task.FromResult(new MercadoLivreOAuthStatus(true, true, "fake status", null, null, null, null, false));
        }

        public Task<MercadoLivreOAuthStatus> RefreshAndCheckAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new MercadoLivreOAuthStatus(true, true, "fake status", null, null, null, null, false));
    }
}
