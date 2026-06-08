using System.Security.Claims;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next;

public static class AuthEndpointsExtensions
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        app.MapPost("/auth/login", async (
            LoginRequest request,
            IOptions<AuthOptions> authOptions,
            LoginAttemptStore attempts,
            IAuditTrail audit,
            HttpContext httpContext,
            CancellationToken ct) =>
        {
            var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var key = $"{request.Username}:{ip}";

            if (attempts.IsLocked(key, DateTimeOffset.UtcNow))
            {
                await audit.WriteAsync("auth.login.locked", request.Username, new { ip }, ct);
                return Results.Json(new { success = false, error = "Conta temporariamente bloqueada" }, statusCode: StatusCodes.Status423Locked);
            }

            var user = authOptions.Value.Users.FirstOrDefault(x => x.Enabled && x.Username.Equals(request.Username, StringComparison.OrdinalIgnoreCase));
            var valid = user is not null
                && !string.IsNullOrEmpty(request.Password)
                && PasswordHasher.Verify(request.Password, user.PasswordHash);

            if (!valid)
            {
                attempts.RegisterFailure(key, DateTimeOffset.UtcNow, 5, TimeSpan.FromMinutes(15));
                await audit.WriteAsync("auth.login.failed", request.Username, new { ip }, ct);
                return Results.Unauthorized();
            }

            attempts.RegisterSuccess(key);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user!.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProps = new AuthenticationProperties();
            if (request.RememberMe)
            {
                authProps.IsPersistent = true;
                authProps.ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30);
            }

            await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), authProps);
            await audit.WriteAsync("auth.login.success", user.Username, new { ip, role = user.Role }, ct);
            return Results.Ok(new { success = true, username = user.Username, role = user.Role });
        }).RequireRateLimiting("login");

        app.MapPost("/auth/logout", async (HttpContext context, IAuditTrail audit, CancellationToken ct) =>
        {
            var actor = context.User.Identity?.Name ?? "anonymous";
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await audit.WriteAsync("auth.logout", actor, new { }, ct);
            return Results.Ok(new { success = true });
        });

        app.MapGet("/auth/me", (HttpContext context) =>
        {
            if (context.User.Identity?.IsAuthenticated != true)
            {
                return Results.Unauthorized();
            }

            return Results.Ok(new
            {
                authenticated = true,
                username = context.User.Identity.Name,
                role = context.User.FindFirst(ClaimTypes.Role)?.Value
            });
        });
    }
}
