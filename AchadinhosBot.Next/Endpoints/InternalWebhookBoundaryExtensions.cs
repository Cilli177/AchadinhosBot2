using System.Net;
using AchadinhosBot.Next.Infrastructure.Security;

namespace AchadinhosBot.Next.Endpoints;

public static class InternalWebhookBoundaryExtensions
{
    public const string BotConversorPath = "/internal/webhook/bot-conversor";

    public static void UseInternalWebhookExposureGuard(this WebApplication app, bool isWorkerRole)
    {
        if (isWorkerRole)
        {
            return;
        }

        app.Use(async (context, next) =>
        {
            if (context.Request.Path.Equals(BotConversorPath, StringComparison.OrdinalIgnoreCase))
            {
                var forwardedFor = context.Request.Headers["X-Forwarded-For"].ToString();
                var realIp = context.Request.Headers["CF-Connecting-IP"].ToString();
                var userAgent = context.Request.Headers.UserAgent.ToString();
                var host = context.Request.Host.HasValue ? context.Request.Host.Value : "unknown";
                var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                app.Logger.LogWarning(
                    "Tentativa indevida de acessar endpoint interno no runtime web. Host={Host} RemoteIp={RemoteIp} RealIp={RealIp} XForwardedFor={XForwardedFor} UserAgent={UserAgent}",
                    host,
                    remoteIp,
                    string.IsNullOrWhiteSpace(realIp) ? "n/a" : realIp,
                    string.IsNullOrWhiteSpace(forwardedFor) ? "n/a" : forwardedFor,
                    string.IsNullOrWhiteSpace(userAgent) ? "n/a" : userAgent);

                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            await next();
        });
    }

    public static bool IsInternalBotConversorRequestAuthorized(
        HttpRequest request,
        string body,
        string? webhookSecret,
        string? fallbackApiKey)
    {
        var remoteIp = request.HttpContext.Connection.RemoteIpAddress;
        return (remoteIp is not null && IPAddress.IsLoopback(remoteIp)) ||
               WebhookRequestAuthorizer.IsAuthorized(request, body, webhookSecret, fallbackApiKey);
    }
}
