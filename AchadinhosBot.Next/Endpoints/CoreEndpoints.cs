using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

public static class CoreEndpoints
{
    public static void MapConverterEndpoint(this WebApplication app)
    {
        app.MapPost("/converter", async (
            ConvertRequest payload,
            HttpContext context,
            IMessageProcessor processor,
            IOptions<WebhookOptions> options,
            CancellationToken ct) =>
        {
            if (!context.Request.Headers.TryGetValue("x-api-key", out var provided) ||
                !SecretComparer.EqualsConstantTime(options.Value.ApiKey, provided.ToString()))
            {
                return Results.Json(new { success = false, error = "forbidden" }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(payload.Text))
            {
                return Results.BadRequest(new { success = false, error = "payload invalido" });
            }

            var result = await processor.ProcessAsync(payload.Text, payload.Source ?? "Webhook", ct);
            return Results.Ok(new
            {
                success = result.Success,
                converted = result.ConvertedText,
                convertedLinks = result.ConvertedLinks,
                source = result.Source
            });
        });
    }

    public static void MapHealthEndpoints(this WebApplication app, bool startTelegramBotWorker, bool startTelegramUserbotWorker)
    {
        app.MapGet("/health", () => Results.Ok(new
        {
            status = "ok",
            service = "AchadinhosBot.Next",
            ts = DateTimeOffset.UtcNow,
            telegramBotWorkerEnabled = startTelegramBotWorker,
            telegramUserbotWorkerEnabled = startTelegramUserbotWorker
        }));

        app.MapGet("/health/live", () => Results.Ok(new
        {
            status = "ok",
            service = "AchadinhosBot.Next",
            kind = "liveness",
            ts = DateTimeOffset.UtcNow
        }));

        app.MapGet("/health/ready", (ITelegramUserbotService userbot) =>
        {
            var userbotReady = !startTelegramUserbotWorker || userbot.IsReady;
            var ready = userbotReady;

            if (!ready)
            {
                return Results.Json(new
                {
                    status = "degraded",
                    kind = "readiness",
                    telegramUserbotReady = userbotReady,
                    ts = DateTimeOffset.UtcNow
                }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            return Results.Ok(new
            {
                status = "ok",
                kind = "readiness",
                telegramUserbotReady = userbotReady,
                ts = DateTimeOffset.UtcNow
            });
        });
    }
}
