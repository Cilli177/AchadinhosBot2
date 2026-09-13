using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Application.Abstractions;
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

public sealed class WhatsAppAdminSafetyEndpointsContractTests
{
    [Fact]
    public async Task UpdateSafety_ForbidsOperatorWithoutPersisting()
    {
        await using var host = await SafetyEndpointHost.CreateAsync();
        var request = host.CreateRequest("operator", new { maxParticipantsAddedPerDay = 12, minMinutesBetweenParticipantAdds = 5, participantCopyAutomationEnabled = true });

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, host.SettingsStore.SaveCalls);
    }

    [Fact]
    public async Task UpdateSafety_RejectsInvalidLimitWithoutPersisting()
    {
        await using var host = await SafetyEndpointHost.CreateAsync();
        var request = host.CreateRequest("admin", new { maxParticipantsAddedPerDay = 0, minMinutesBetweenParticipantAdds = 5, participantCopyAutomationEnabled = true });

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, host.SettingsStore.SaveCalls);
    }

    [Fact]
    public async Task UpdateSafety_PersistsNormalizedLimitsForAdmin()
    {
        await using var host = await SafetyEndpointHost.CreateAsync();
        var request = host.CreateRequest("admin", new { maxParticipantsAddedPerDay = 12, minMinutesBetweenParticipantAdds = 5, participantCopyAutomationEnabled = true, instanceName = "main" });

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, host.SettingsStore.SaveCalls);
        var automation = host.SettingsStore.Settings.WhatsAppAdminAutomation!;
        Assert.Equal(12, automation.MaxParticipantsAddedPerDay);
        Assert.Equal(5, automation.MinMinutesBetweenParticipantAdds);
        Assert.True(automation.ParticipantCopyAutomationEnabled);
        Assert.Contains(automation.InstanceParticipantAddSafety, item => item.InstanceName == "main" && item.MaxParticipantsAddedPerDay == 12 && item.MinMinutesBetweenParticipantAdds == 5);
    }

    private sealed class SafetyEndpointHost : IAsyncDisposable
    {
        private readonly WebApplication _app;

        private SafetyEndpointHost(WebApplication app, HttpClient client, TestSettingsStore settingsStore)
        {
            _app = app;
            Client = client;
            SettingsStore = settingsStore;
        }

        internal HttpClient Client { get; }
        internal TestSettingsStore SettingsStore { get; }

        internal HttpRequestMessage CreateRequest(string role, object payload)
        {
            var request = new HttpRequestMessage(HttpMethod.Put, "/api/admin/whatsapp/automation/safety") { Content = JsonContent.Create(payload) };
            request.Headers.Add("X-Test-Role", role);
            return request;
        }

        internal static async Task<SafetyEndpointHost> CreateAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddAuthentication(TestAuthenticationHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestAuthenticationHandler.SchemeName, _ => { });
            builder.Services.AddAuthorization(options => options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin")));
            var settingsStore = new TestSettingsStore();
            builder.Services.AddSingleton<ISettingsStore>(settingsStore);

            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapWhatsAppAdminSafetyEndpoints();
            await app.StartAsync();
            return new SafetyEndpointHost(app, app.GetTestClient(), settingsStore);
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
        internal const string SchemeName = "WhatsAppAdminSafetyTest";

        public TestAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder) { }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var role = Request.Headers["X-Test-Role"].SingleOrDefault();
            if (string.IsNullOrWhiteSpace(role)) return Task.FromResult(AuthenticateResult.NoResult());
            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, role), new Claim(ClaimTypes.Role, role)], SchemeName);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }

    private sealed class TestSettingsStore : ISettingsStore
    {
        internal int SaveCalls { get; private set; }
        internal AutomationSettings Settings { get; } = new();

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(Settings);

        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken)
        {
            SaveCalls++;
            return Task.CompletedTask;
        }
    }
}
