using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Endpoints;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class SettingsEndpointsContractTests
{
    [Fact]
    public async Task Versions_AllowsOperatorReadAccess()
    {
        await using var host = await SettingsEndpointHost.CreateAsync();
        var request = CreateOperatorRequest(HttpMethod.Get, "/api/settings/versions");

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<VersionResponse>();
        Assert.True(body!.Success);
        Assert.Single(body.Versions);
    }

    [Fact]
    public async Task Update_ForbidsOperatorWithoutPersistingOrAuditing()
    {
        await using var host = await SettingsEndpointHost.CreateAsync();
        var request = CreateOperatorRequest(HttpMethod.Put, "/api/settings");
        request.Content = JsonContent.Create(new AutomationSettings());

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, host.SettingsStore.SaveCalls);
        Assert.Empty(host.Audit.Actions);
    }

    [Fact]
    public async Task Restore_ForbidsOperatorWithoutRestoringOrAuditing()
    {
        await using var host = await SettingsEndpointHost.CreateAsync();
        var request = CreateOperatorRequest(HttpMethod.Post, "/api/settings/restore");
        request.Content = JsonContent.Create(new { versionFileName = "settings.20260911.json" });

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, host.VersionStore.RestoreCalls);
        Assert.Empty(host.Audit.Actions);
    }

    [Fact]
    public async Task DedicatedAdminApiKey_AllowsUpdateAndRestore()
    {
        await using var host = await SettingsEndpointHost.CreateAsync();

        var update = new HttpRequestMessage(HttpMethod.Put, "/api/settings")
        {
            Content = JsonContent.Create(new AutomationSettings())
        };
        update.Headers.Add("X-Admin-Key", SettingsEndpointHost.DedicatedAdminApiKey);
        var updateResponse = await host.Client.SendAsync(update);

        var restore = new HttpRequestMessage(HttpMethod.Post, "/api/settings/restore")
        {
            Content = JsonContent.Create(new { versionFileName = "settings.20260911.json" })
        };
        restore.Headers.Add("X-Admin-Key", SettingsEndpointHost.DedicatedAdminApiKey);
        var restoreResponse = await host.Client.SendAsync(restore);

        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, restoreResponse.StatusCode);
        Assert.Equal(1, host.SettingsStore.SaveCalls);
        Assert.Equal(1, host.VersionStore.RestoreCalls);
        Assert.Equal(["settings.updated", "settings.restored"], host.Audit.Actions);
    }

    private static HttpRequestMessage CreateOperatorRequest(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-Test-Role", "operator");
        return request;
    }

    private sealed record VersionResponse(bool Success, List<SettingsVersionInfo> Versions);

    private sealed class SettingsEndpointHost : IAsyncDisposable
    {
        internal const string DedicatedAdminApiKey = "dedicated-admin-test-key";
        private readonly WebApplication _app;

        private SettingsEndpointHost(WebApplication app, HttpClient client, TestSettingsStore settingsStore, TestSettingsVersionStore versionStore, TestAuditTrail audit)
        {
            _app = app;
            Client = client;
            SettingsStore = settingsStore;
            VersionStore = versionStore;
            Audit = audit;
        }

        internal HttpClient Client { get; }
        internal TestSettingsStore SettingsStore { get; }
        internal TestSettingsVersionStore VersionStore { get; }
        internal TestAuditTrail Audit { get; }

        internal static async Task<SettingsEndpointHost> CreateAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.Configure<AuthOptions>(options => options.AdminApiKey = DedicatedAdminApiKey);
            builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "SettingsEndpointTestSelector";
                    options.DefaultChallengeScheme = "SettingsEndpointTestSelector";
                })
                .AddPolicyScheme("SettingsEndpointTestSelector", null, options =>
                {
                    options.ForwardDefaultSelector = context => context.Request.Headers.ContainsKey(AdminAuthenticationSchemes.HeaderName)
                        ? AdminAuthenticationSchemes.AdminApiKey
                        : TestAuthenticationHandler.SchemeName;
                })
                .AddScheme<AuthenticationSchemeOptions, AdminApiKeyAuthenticationHandler>(AdminAuthenticationSchemes.AdminApiKey, _ => { })
                .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestAuthenticationHandler.SchemeName, _ => { });
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("ReadAccess", policy => policy.RequireRole("admin", "operator"));
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
            });

            var settingsStore = new TestSettingsStore();
            var versionStore = new TestSettingsVersionStore();
            var audit = new TestAuditTrail();
            builder.Services.AddSingleton<ISettingsStore>(settingsStore);
            builder.Services.AddSingleton<ISettingsVersionStore>(versionStore);
            builder.Services.AddSingleton<IAuditTrail>(audit);

            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();
            var api = app.MapGroup("/api").RequireAuthorization("ReadAccess");
            api.MapSettingsEndpoints(_ => Array.Empty<string>(), static (_, _, _, _) => "https://example.test", static _ => { });
            await app.StartAsync();

            return new SettingsEndpointHost(app, app.GetTestClient(), settingsStore, versionStore, audit);
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
        internal const string SchemeName = "SettingsEndpointTest";

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

            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, role), new Claim(ClaimTypes.Role, role)], SchemeName);
            var principal = new ClaimsPrincipal(identity);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
        }
    }

    private sealed class TestSettingsStore : ISettingsStore
    {
        internal int SaveCalls { get; private set; }

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(new AutomationSettings());

        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken)
        {
            SaveCalls++;
            return Task.CompletedTask;
        }
    }

    private sealed class TestSettingsVersionStore : ISettingsVersionStore
    {
        internal int RestoreCalls { get; private set; }

        public Task<IReadOnlyList<SettingsVersionInfo>> ListVersionsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SettingsVersionInfo>>([new("settings.20260911.json", DateTimeOffset.UtcNow, 42)]);

        public Task<AutomationSettings?> RestoreAsync(string versionFileName, CancellationToken cancellationToken)
        {
            RestoreCalls++;
            return Task.FromResult<AutomationSettings?>(new AutomationSettings());
        }
    }

    private sealed class TestAuditTrail : IAuditTrail
    {
        internal List<string> Actions { get; } = new();

        public Task WriteAsync(string action, string actor, object details, CancellationToken cancellationToken)
        {
            Actions.Add(action);
            return Task.CompletedTask;
        }
    }
}
