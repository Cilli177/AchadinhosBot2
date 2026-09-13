using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
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

public sealed class WhatsAppExecutionEndpointsContractTests
{
    [Fact]
    public async Task ManualCopy_ForbidsOperatorBeforeAnyTransportCall()
    {
        await using var host = await Host.CreateAsync();
        var response = await host.Client.SendAsync(host.Request("operator"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, host.Transport.ReadCalls);
        Assert.Equal(0, host.Transport.AddCalls);
        Assert.Equal(0, host.Queue.GetState().PendingCount);
    }

    [Fact]
    public async Task ManualCopy_QueuesAdminRequestWithoutAddingParticipantsDuringHttpRequest()
    {
        await using var host = await Host.CreateAsync();
        var response = await host.Client.SendAsync(host.Request("admin"));
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(1, host.Transport.ReadCalls);
        Assert.Equal(0, host.Transport.AddCalls);
        var item = Assert.Single(host.Queue.GetState().Items);
        Assert.Equal("manual-copy", item.Kind);
        Assert.Equal("queued", item.Status);
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private Host(WebApplication app, HttpClient client, WhatsAppAutomationQueueService queue, Transport transport) { _app = app; Client = client; Queue = queue; Transport = transport; }
        internal HttpClient Client { get; } internal WhatsAppAutomationQueueService Queue { get; } internal Transport Transport { get; }
        internal HttpRequestMessage Request(string role) { var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/whatsapp/groups/copy-participants") { Content = JsonContent.Create(new { sourceGroupId = "source", targetGroupId = "target", participantIds = new[] { "person" } }) }; request.Headers.Add("X-Test-Role", role); return request; }
        internal static async Task<Host> CreateAsync()
        {
            var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
            builder.Services.AddAuthentication(Auth.SchemeName).AddScheme<AuthenticationSchemeOptions, Auth>(Auth.SchemeName, _ => { }); builder.Services.AddAuthorization(x => x.AddPolicy("AdminOnly", p => p.RequireRole("admin")));
            var queue = new WhatsAppAutomationQueueService(); var transport = new Transport();
            builder.Services.AddSingleton(queue); builder.Services.AddSingleton<IWhatsAppTransport>(transport); builder.Services.AddSingleton<ISettingsStore>(new Store());
            var app = builder.Build(); app.UseAuthentication(); app.UseAuthorization(); app.MapWhatsAppExecutionEndpoints(); await app.StartAsync(); return new Host(app, app.GetTestClient(), queue, transport);
        }
        public async ValueTask DisposeAsync() { Client.Dispose(); await _app.StopAsync(); await _app.DisposeAsync(); }
    }

    private sealed class Auth : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        internal const string SchemeName = "execution-test";
        public Auth(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() { var role = Request.Headers["X-Test-Role"].SingleOrDefault(); if (string.IsNullOrWhiteSpace(role)) return Task.FromResult(AuthenticateResult.NoResult()); var id = new ClaimsIdentity([new Claim(ClaimTypes.Role, role)], SchemeName); return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(id), SchemeName))); }
    }

    private sealed class Store : ISettingsStore
    {
        private readonly AutomationSettings _settings = new() { WhatsAppAdminAutomation = new WhatsAppAdminAutomationSettings { ParticipantCopyAutomationEnabled = true } };
        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(_settings);
        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class Transport : IWhatsAppTransport
    {
        internal int ReadCalls { get; private set; } internal int AddCalls { get; private set; }
        public Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken) { ReadCalls++; return Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>()); }
        public Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken) { AddCalls++; return Task.FromResult(new WhatsAppSendResult(true, "ok")); }
        public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppConnectResult(true, null, "ok")); public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppInstanceResult(true, null, "ok")); public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<WhatsAppGroupInfo>>(Array.Empty<WhatsAppGroupInfo>()); public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, "ok")); public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, "ok")); public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, "ok")); public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, "ok"));
    }
}
