using Microsoft.AspNetCore.Antiforgery;

namespace AchadinhosBot.Next.Infrastructure.Security;

public sealed class CookieRequestForgeryProtectionMiddleware
{
    private static readonly HashSet<string> UnsafeMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        HttpMethods.Post,
        HttpMethods.Put,
        HttpMethods.Patch,
        HttpMethods.Delete
    };

    private readonly RequestDelegate _next;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<CookieRequestForgeryProtectionMiddleware> _logger;

    public CookieRequestForgeryProtectionMiddleware(
        RequestDelegate next,
        IAntiforgery antiforgery,
        ILogger<CookieRequestForgeryProtectionMiddleware> logger)
    {
        _next = next;
        _antiforgery = antiforgery;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!UnsafeMethods.Contains(context.Request.Method))
        {
            await _next(context);
            return;
        }

        var isCookieAuthenticated = context.User.Identity?.IsAuthenticated == true &&
            string.Equals(context.User.Identity.AuthenticationType, AdminAuthenticationSchemes.Cookie, StringComparison.Ordinal);
        var isLogin = context.Request.Path.Equals("/auth/login", StringComparison.OrdinalIgnoreCase);

        if (!isCookieAuthenticated && !isLogin)
        {
            await _next(context);
            return;
        }

        if (!HasSafeBrowserOrigin(context.Request))
        {
            _logger.LogWarning("Requisicao mutavel por cookie rejeitada por origem. Path={Path}", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        if (!isCookieAuthenticated)
        {
            await _next(context);
            return;
        }

        try
        {
            await _antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        await _next(context);
    }

    private static bool HasSafeBrowserOrigin(HttpRequest request)
    {
        var origin = request.Headers.Origin.ToString();
        if (!string.IsNullOrWhiteSpace(origin))
        {
            if (string.Equals(origin, "null", StringComparison.OrdinalIgnoreCase) ||
                !Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
            {
                return false;
            }

            var expectedOrigin = new Uri($"{request.Scheme}://{request.Host}");
            return Uri.Compare(originUri, expectedOrigin, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0;
        }

        return !string.Equals(request.Headers["Sec-Fetch-Site"], "cross-site", StringComparison.OrdinalIgnoreCase);
    }
}

public static class CookieRequestForgeryProtectionApplicationBuilderExtensions
{
    public static IApplicationBuilder UseCookieRequestForgeryProtection(this IApplicationBuilder app)
        => app.UseMiddleware<CookieRequestForgeryProtectionMiddleware>();
}
