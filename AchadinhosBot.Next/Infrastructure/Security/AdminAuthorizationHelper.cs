using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using AchadinhosBot.Next.Infrastructure.Security;

namespace AchadinhosBot.Next.Infrastructure.Security;

public static class AdminAuthorizationHelper
{
    public static bool IsAdminAuthorized(HttpContext ctx, string apiKey)
    {
        if (ctx.User.Identity?.IsAuthenticated == true)
        {
            var role = ctx.User.FindFirst(ClaimTypes.Role)?.Value;
            if (string.Equals(role, "admin", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(role, "operator", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (ctx.Request.Headers.TryGetValue("X-Admin-Key", out var provided))
            return !string.IsNullOrWhiteSpace(provided.ToString()) &&
                   SecretComparer.EqualsConstantTime(apiKey, provided.ToString());
        
        return false;
    }
}
