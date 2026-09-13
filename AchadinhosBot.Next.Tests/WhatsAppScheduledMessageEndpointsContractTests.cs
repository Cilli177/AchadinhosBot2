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

public sealed class WhatsAppScheduledMessageEndpointsContractTests
{
    [Fact]
    public async Task Create_ForbidsOperatorWithoutPersisting()
    {
        await using var host = await Host.CreateAsync();
        var response = await host.Client.SendAsync(host.Request("operator", null));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, host.Store.SaveCalls);
    }

    [Fact]
    public async Task Create_RejectsInternalImageUrlWithoutPersisting()
    {
        await using var host = await Host.CreateAsync();
        var response = await host.Client.SendAsync(host.Request("admin", "http://localhost/private.png"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, host.Store.SaveCalls);
    }

    [Fact]
    public async Task Create_PersistsScheduleForAdmin()
    {
        await using var host = await Host.CreateAsync();
        var response = await host.Client.SendAsync(host.Request("admin", "https://cdn.example.test/image.png"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, host.Store.SaveCalls);
        var schedule = Assert.Single(host.Store.Settings.WhatsAppAdminAutomation!.ScheduledGroupMessages);
        Assert.Equal("target", schedule.TargetGroupId); Assert.Equal("Olá", schedule.Text); Assert.Equal(1, schedule.IntervalMinutes);
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private Host(WebApplication app, HttpClient client, Store store) { _app = app; Client = client; Store = store; }
        internal HttpClient Client { get; } internal Store Store { get; }
        internal HttpRequestMessage Request(string role, string? imageUrl) { var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/whatsapp/message-schedules") { Content = JsonContent.Create(new { targetGroupId = "target", text = "Olá", intervalMinutes = 0, imageUrl }) }; request.Headers.Add("X-Test-Role", role); return request; }
        internal static async Task<Host> CreateAsync() { var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer(); builder.Services.AddAuthentication(Auth.SchemeName).AddScheme<AuthenticationSchemeOptions, Auth>(Auth.SchemeName, _ => { }); builder.Services.AddAuthorization(x => x.AddPolicy("AdminOnly", p => p.RequireRole("admin"))); var store = new Store(); builder.Services.AddSingleton<ISettingsStore>(store); var app = builder.Build(); app.UseAuthentication(); app.UseAuthorization(); app.MapWhatsAppScheduledMessageEndpoints(); await app.StartAsync(); return new Host(app, app.GetTestClient(), store); }
        public async ValueTask DisposeAsync() { Client.Dispose(); await _app.StopAsync(); await _app.DisposeAsync(); }
    }

    private sealed class Auth : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        internal const string SchemeName = "scheduled-message-test";
        public Auth(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() { var role = Request.Headers["X-Test-Role"].SingleOrDefault(); if (string.IsNullOrWhiteSpace(role)) return Task.FromResult(AuthenticateResult.NoResult()); var identity = new ClaimsIdentity([new Claim(ClaimTypes.Role, role)], SchemeName); return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName))); }
    }

    private sealed class Store : ISettingsStore
    {
        internal int SaveCalls { get; private set; } internal AutomationSettings Settings { get; } = new();
        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(Settings);
        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) { SaveCalls++; return Task.CompletedTask; }
    }
}
