using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Endpoints;
using AchadinhosBot.Next.Infrastructure.Storage;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class LogsMaintenanceEndpointsContractTests
{
    [Theory]
    [InlineData("/api/logs/clicks/clear", "logs.clicks.clear")]
    [InlineData("/api/logs/instagram-ai/clear", "logs.instagram_ai.clear")]
    [InlineData("/api/logs/instagram-publish/clear", "logs.instagram_publish.clear")]
    [InlineData("/api/logs/conversions/clear", "logs.conversions.clear")]
    [InlineData("/api/logs/media/clear", "logs.media.clear")]
    [InlineData("/api/logs/whatsapp-official-blocked/clear", "logs.whatsapp_official_blocked.clear")]
    public async Task ClearRoutes_ForbidOperatorAndAllowAdmin(string path, string auditAction)
    {
        await using var host = await Host.CreateAsync();
        var op = Request(path, "operator");
        var forbidden = await host.Client.SendAsync(op);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        Assert.Equal(0, host.Tracker.ClearCalls);
        Assert.Empty(host.Audit.Actions);

        var admin = Request(path, "admin");
        var ok = await host.Client.SendAsync(admin);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(0, host.Tracker.ClearCalls);
        Assert.Equal([$"{auditAction}.requested", auditAction], host.Audit.Actions);
    }

    [Fact]
    public async Task ClearRoutes_RequireExplicitConfirmationBeforeAuditingOrChangingLogs()
    {
        await using var host = await Host.CreateAsync();
        using var request = Request("/api/logs/conversions/clear", "admin", "NO");
        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, host.Tracker.ClearCalls);
        Assert.Empty(host.Audit.Actions);
    }

    private static HttpRequestMessage Request(string path, string role, string confirmation = "CLEAR_LOGS") { var r = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(new { confirmation }) }; r.Headers.Add("X-Role", role); return r; }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app; private readonly string _dataRoot; internal HttpClient Client { get; } internal Tracker Tracker { get; } internal Audit Audit { get; }
        private Host(WebApplication app, HttpClient client, Tracker tracker, Audit audit, string dataRoot) { _app = app; Client = client; Tracker = tracker; Audit = audit; _dataRoot = dataRoot; }
        internal static async Task<Host> CreateAsync()
        {
            var b = WebApplication.CreateBuilder(); b.WebHost.UseTestServer();
            b.Services.AddAuthentication(Auth.SchemeName).AddScheme<AuthenticationSchemeOptions, Auth>(Auth.SchemeName, _ => { });
            b.Services.AddAuthorization(o => { o.AddPolicy("ReadAccess", p => p.RequireRole("admin", "operator")); o.AddPolicy("AdminOnly", p => p.RequireRole("admin")); });
            var t = new Tracker(); var a = new Audit(); var dataRoot = Path.Combine(Path.GetTempPath(), "achadinhos-log-endpoint-tests", Guid.NewGuid().ToString("N")); b.Services.AddSingleton(t); b.Services.AddSingleton<IAuditTrail>(a); b.Services.AddSingleton<ILogMaintenanceLockCoordinator, LogMaintenanceLockCoordinator>(); b.Services.AddSingleton(sp => new LogSnapshotService(sp.GetRequiredService<ILogMaintenanceLockCoordinator>(), dataRoot));
            b.Services.AddSingleton<IClickLogStore, Click>(); b.Services.AddSingleton<IInstagramAiLogStore, Ai>(); b.Services.AddSingleton<IInstagramPublishLogStore, Publish>(); b.Services.AddSingleton<IConversionLogStore, Conversion>(); b.Services.AddSingleton<IMediaFailureLogStore, Media>(); b.Services.AddSingleton<IOfficialWhatsAppBlockedOfferStore, Blocked>();
            var app = b.Build(); app.UseAuthentication(); app.UseAuthorization(); app.MapGroup("/api").RequireAuthorization("ReadAccess").MapLogsMaintenanceEndpoints(); await app.StartAsync(); return new(app, app.GetTestClient(), t, a, dataRoot);
        }
        public async ValueTask DisposeAsync() { Client.Dispose(); await _app.StopAsync(); await _app.DisposeAsync(); if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); }
    }
    private sealed class Auth(IOptionsMonitor<AuthenticationSchemeOptions> o, ILoggerFactory l, UrlEncoder e) : AuthenticationHandler<AuthenticationSchemeOptions>(o,l,e) { internal const string SchemeName="LogsMaintenanceTest"; protected override Task<AuthenticateResult> HandleAuthenticateAsync() { var role=Request.Headers["X-Role"].SingleOrDefault(); return string.IsNullOrWhiteSpace(role) ? Task.FromResult(AuthenticateResult.NoResult()) : Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Role,role)],SchemeName)),SchemeName))); } }
    private sealed class Tracker { internal int ClearCalls; }
    private sealed class Audit : IAuditTrail { internal List<string> Actions { get; }=[]; public Task WriteAsync(string action,string actor,object details,CancellationToken ct){Actions.Add(action);return Task.CompletedTask;} }
    private abstract class Store(Tracker t) : ILogMaintenanceScope { public string ScopeId => $"test-{GetType().Name.ToLowerInvariant()}"; public IReadOnlyList<string> RelativePaths => ["events.jsonl"]; protected Task Clear(){t.ClearCalls++;return Task.CompletedTask;} }
    private sealed class Click(Tracker t):Store(t),IClickLogStore { public Task AppendAsync(ClickLogEntry e,string? c,CancellationToken ct)=>Task.CompletedTask; public Task<IReadOnlyList<ClickLogEntry>> QueryAsync(string? c,string? s,int l,CancellationToken ct)=>Task.FromResult<IReadOnlyList<ClickLogEntry>>([]); public Task ClearAsync(string? c,CancellationToken ct)=>Clear(); }
    private sealed class Ai(Tracker t):Store(t),IInstagramAiLogStore { public Task AppendAsync(InstagramAiLogEntry e,CancellationToken ct)=>Task.CompletedTask; public Task<IReadOnlyList<InstagramAiLogEntry>> ListAsync(int n,CancellationToken ct)=>Task.FromResult<IReadOnlyList<InstagramAiLogEntry>>([]); public Task ClearAsync(CancellationToken ct)=>Clear(); }
    private sealed class Publish(Tracker t):Store(t),IInstagramPublishLogStore { public Task AppendAsync(InstagramPublishLogEntry e,CancellationToken ct)=>Task.CompletedTask; public Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int n,CancellationToken ct)=>Task.FromResult<IReadOnlyList<InstagramPublishLogEntry>>([]); public Task ClearAsync(CancellationToken ct)=>Clear(); }
    private sealed class Conversion(Tracker t):Store(t),IConversionLogStore { public Task AppendAsync(ConversionLogEntry e,CancellationToken ct)=>Task.CompletedTask; public Task<IReadOnlyList<ConversionLogEntry>> QueryAsync(ConversionLogQuery q,CancellationToken ct)=>Task.FromResult<IReadOnlyList<ConversionLogEntry>>([]); public Task ClearAsync(CancellationToken ct)=>Clear(); }
    private sealed class Media(Tracker t):Store(t),IMediaFailureLogStore { public Task AppendAsync(MediaFailureEntry e,CancellationToken ct)=>Task.CompletedTask; public Task<IReadOnlyList<MediaFailureEntry>> ListAsync(int n,CancellationToken ct)=>Task.FromResult<IReadOnlyList<MediaFailureEntry>>([]); public Task ClearAsync(CancellationToken ct)=>Clear(); }
    private sealed class Blocked(Tracker t):Store(t),IOfficialWhatsAppBlockedOfferStore { public Task AppendAsync(OfficialWhatsAppBlockedOfferEntry e,CancellationToken ct)=>Task.CompletedTask; public Task<IReadOnlyList<OfficialWhatsAppBlockedOfferEntry>> ListAsync(int n,CancellationToken ct)=>Task.FromResult<IReadOnlyList<OfficialWhatsAppBlockedOfferEntry>>([]); public Task ClearAsync(CancellationToken ct)=>Clear(); }
}
