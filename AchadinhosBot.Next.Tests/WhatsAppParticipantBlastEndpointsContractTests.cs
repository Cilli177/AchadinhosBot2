using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Endpoints;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppParticipantBlastEndpointsContractTests
{
    [Fact]
    public async Task CreateBlast_ForbidsOperatorBeforeHandlerDependenciesAreResolved()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthentication(Auth.SchemeName).AddScheme<AuthenticationSchemeOptions, Auth>(Auth.SchemeName, _ => { });
        builder.Services.AddAuthorization(x => x.AddPolicy("AdminOnly", p => p.RequireRole("admin")));
        var app = builder.Build();
        app.UseAuthentication(); app.UseAuthorization(); app.MapWhatsAppParticipantBlastEndpoints();
        await app.StartAsync();
        try
        {
            var client = app.GetTestClient();
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/whatsapp/groups/blast-participants/scheduled")
            {
                Content = JsonContent.Create(new { sourceGroupId = "source", participantIds = new[] { "person" }, linkUrl = "https://chat.whatsapp.com/InviteCode", linkConfirmation = "InviteCode", message = "convite" })
            };
            request.Headers.Add("X-Test-Role", "operator");
            var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    private sealed class Auth : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        internal const string SchemeName = "blast-endpoint-test";
        public Auth(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var role = Request.Headers["X-Test-Role"].SingleOrDefault();
            if (string.IsNullOrWhiteSpace(role)) return Task.FromResult(AuthenticateResult.NoResult());
            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Role, role)], SchemeName);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }
}
