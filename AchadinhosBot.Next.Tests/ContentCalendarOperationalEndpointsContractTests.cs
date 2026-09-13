using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Endpoints;
using AchadinhosBot.Next.Infrastructure.Content;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class ContentCalendarOperationalEndpointsContractTests
{
    [Fact]
    public async Task ProcessDue_OnlyAdminCanQueueAndItNeverExecutesWorkInHttp()
    {
        await using var host = await Host.CreateAsync();
        using var denied = new HttpRequestMessage(HttpMethod.Post, "/api/content-calendar/process-due"); denied.Headers.Add("X-Role", "operator");
        Assert.Equal(HttpStatusCode.Forbidden, (await host.Client.SendAsync(denied)).StatusCode);
        Assert.Equal(0, host.Dispatcher.Calls);
        Assert.Empty(host.Audit.Actions);

        using var accepted = new HttpRequestMessage(HttpMethod.Post, "/api/content-calendar/process-due"); accepted.Headers.Add("X-Role", "admin");
        Assert.Equal(HttpStatusCode.Accepted, (await host.Client.SendAsync(accepted)).StatusCode);
        Assert.Equal(1, host.Dispatcher.Calls);
        Assert.Equal(["content_calendar.process_due.queued"], host.Audit.Actions);
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app; internal HttpClient Client { get; } internal Dispatcher Dispatcher { get; } internal Audit Audit { get; }
        private Host(WebApplication app, HttpClient client, Dispatcher dispatcher, Audit audit) { _app = app; Client = client; Dispatcher = dispatcher; Audit = audit; }
        internal static async Task<Host> CreateAsync()
        {
            var b = WebApplication.CreateBuilder(); b.WebHost.UseTestServer();
            b.Services.AddAuthentication(Auth.SchemeName).AddScheme<AuthenticationSchemeOptions, Auth>(Auth.SchemeName, _ => { });
            b.Services.AddAuthorization(o => o.AddPolicy("AdminOnly", p => p.RequireRole("admin")));
            var dispatcher = new Dispatcher(); var audit = new Audit(); b.Services.AddSingleton<IContentCalendarDispatchService>(dispatcher); b.Services.AddSingleton<IAuditTrail>(audit);
            var app = b.Build(); app.UseAuthentication(); app.UseAuthorization(); app.MapGroup("/api").MapContentCalendarOperationalEndpoints(); await app.StartAsync(); return new(app, app.GetTestClient(), dispatcher, audit);
        }
        public async ValueTask DisposeAsync() { Client.Dispose(); await _app.StopAsync(); await _app.DisposeAsync(); }
    }

    private sealed class Dispatcher : IContentCalendarDispatchService { internal int Calls; public Task<ContentCalendarDispatchResult> QueueProcessDueAsync(string actor, CancellationToken ct) { Calls++; return Task.FromResult(new ContentCalendarDispatchResult("message-id", "rabbitmq", false)); } }
    private sealed class Audit : IAuditTrail { internal List<string> Actions { get; } = []; public Task WriteAsync(string action, string actor, object details, CancellationToken ct) { Actions.Add(action); return Task.CompletedTask; } }
    private sealed class Auth(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder) { internal const string SchemeName = "CalendarTest"; protected override Task<AuthenticateResult> HandleAuthenticateAsync() { var role = Request.Headers["X-Role"].SingleOrDefault(); return string.IsNullOrWhiteSpace(role) ? Task.FromResult(AuthenticateResult.NoResult()) : Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Role, role)], SchemeName)), SchemeName))); } }
}
