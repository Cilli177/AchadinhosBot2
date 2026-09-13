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

public sealed class WhatsAppParticipantCopyScheduleEndpointsContractTests
{
    [Fact]
    public async Task Create_ForbidsOperatorWithoutReadingGroupsOrPersisting()
    {
        await using var host = await CopyScheduleHost.CreateAsync();
        var response = await host.Client.SendAsync(host.CreateRequest("operator", new { sourceGroupId = "source", targetGroupId = "target", batchSize = 5, intervalMinutes = 10, participantIds = new[] { "a" } }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, host.SettingsStore.SaveCalls);
        Assert.Equal(0, host.Gateway.GroupReadCalls);
        Assert.Equal(0, host.Gateway.SendCalls);
    }

    [Fact]
    public async Task Create_PersistsOnlyEligibleParticipantsWithoutSending()
    {
        await using var host = await CopyScheduleHost.CreateAsync();
        host.Gateway.ParticipantsByGroup["target"] = ["already-there"];
        var response = await host.Client.SendAsync(host.CreateRequest("admin", new { sourceGroupId = "source", targetGroupId = "target", batchSize = 5, intervalMinutes = 1, participantIds = new[] { "new", "already-there", "new" }, instanceName = "main" }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, host.SettingsStore.SaveCalls);
        Assert.Equal(1, host.Gateway.GroupReadCalls);
        Assert.Equal(0, host.Gateway.SendCalls);
        var schedule = Assert.Single(host.SettingsStore.Settings.WhatsAppAdminAutomation!.ParticipantCopySchedules);
        Assert.Equal(["new"], schedule.PendingParticipantIds);
        Assert.Equal(1, schedule.SkippedParticipants);
        Assert.Equal("main", schedule.InstanceName);
    }

    private sealed class CopyScheduleHost : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private CopyScheduleHost(WebApplication app, HttpClient client, TestSettingsStore settingsStore, RecordingGateway gateway) { _app = app; Client = client; SettingsStore = settingsStore; Gateway = gateway; }
        internal HttpClient Client { get; }
        internal TestSettingsStore SettingsStore { get; }
        internal RecordingGateway Gateway { get; }
        internal HttpRequestMessage CreateRequest(string role, object payload)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/whatsapp/copy-schedules") { Content = JsonContent.Create(payload) };
            request.Headers.Add("X-Test-Role", role);
            return request;
        }
        internal static async Task<CopyScheduleHost> CreateAsync()
        {
            var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
            builder.Services.AddAuthentication(TestAuthenticationHandler.SchemeName).AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestAuthenticationHandler.SchemeName, _ => { });
            builder.Services.AddAuthorization(options => options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin")));
            var settingsStore = new TestSettingsStore(); var gateway = new RecordingGateway();
            builder.Services.AddSingleton<ISettingsStore>(settingsStore); builder.Services.AddSingleton<IWhatsAppGateway>(gateway);
            var app = builder.Build(); app.UseAuthentication(); app.UseAuthorization(); app.MapWhatsAppParticipantCopyScheduleEndpoints(); await app.StartAsync();
            return new CopyScheduleHost(app, app.GetTestClient(), settingsStore, gateway);
        }
        public async ValueTask DisposeAsync() { Client.Dispose(); await _app.StopAsync(); await _app.DisposeAsync(); }
    }

    private sealed class TestAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        internal const string SchemeName = "CopyScheduleTest";
        public TestAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }
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
        internal AutomationSettings Settings { get; } = new() { WhatsAppAdminAutomation = new WhatsAppAdminAutomationSettings { ParticipantCopyAutomationEnabled = true } };
        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(Settings);
        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) { SaveCalls++; return Task.CompletedTask; }
    }

    private sealed class RecordingGateway : IWhatsAppGateway
    {
        internal Dictionary<string, IReadOnlyList<string>> ParticipantsByGroup { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal int GroupReadCalls { get; private set; }
        internal int SendCalls { get; private set; }
        public Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken) { GroupReadCalls++; return Task.FromResult(ParticipantsByGroup.GetValueOrDefault(groupId, Array.Empty<string>())); }
        public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppConnectResult(true, null, "ok"));
        public Task<IReadOnlyList<WhatsAppInstanceInfo>> FetchInstancesAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<WhatsAppInstanceInfo>>(Array.Empty<WhatsAppInstanceInfo>());
        public Task<WhatsAppConnectResult> TestConnectionAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppConnectResult(true, null, "ok"));
        public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppInstanceResult(true, null, "ok"));
        public Task<WhatsAppConnectionSnapshot> GetConnectionSnapshotAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppConnectionSnapshot(true, "connected", null, "ok"));
        public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<WhatsAppGroupInfo>>(Array.Empty<WhatsAppGroupInfo>());
        public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken) { SendCalls++; return Task.FromResult(new WhatsAppSendResult(true, "ok")); }
        public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken) { SendCalls++; return Task.FromResult(new WhatsAppSendResult(true, "ok")); }
        public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken) { SendCalls++; return Task.FromResult(new WhatsAppSendResult(true, "ok")); }
        public Task<WhatsAppSendResult> UpdateProfilePictureAsync(string? instanceName, string picture, CancellationToken cancellationToken) { SendCalls++; return Task.FromResult(new WhatsAppSendResult(true, "ok")); }
        public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken) { SendCalls++; return Task.FromResult(new WhatsAppSendResult(true, "ok")); }
        public Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken) { SendCalls++; return Task.FromResult(new WhatsAppSendResult(true, "ok")); }
    }
}
