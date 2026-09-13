using System.Security.Claims;
using System.Text.Encodings.Web;
using AchadinhosBot.Next.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Security;

public static class AdminAuthenticationSchemes
{
    public const string Cookie = "Cookies";
    public const string AdminApiKey = "AdminApiKey";
    public const string Selector = "AdminOrCookie";
    public const string HeaderName = "X-Admin-Key";
}

public sealed class AdminApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IOptionsMonitor<AuthOptions> _authOptions;

    public AdminApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IOptionsMonitor<AuthOptions> authOptions)
        : base(options, logger, encoder)
    {
        _authOptions = authOptions;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(AdminAuthenticationSchemes.HeaderName, out var provided) ||
            string.IsNullOrWhiteSpace(provided.ToString()))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!SecretComparer.EqualsConstantTime(_authOptions.CurrentValue.AdminApiKey, provided.ToString()))
        {
            return Task.FromResult(AuthenticateResult.Fail("Chave administrativa invalida."));
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, "api_key"),
            new Claim(ClaimTypes.Role, "admin")
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
