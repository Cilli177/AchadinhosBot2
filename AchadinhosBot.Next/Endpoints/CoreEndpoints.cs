using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace AchadinhosBot.Next.Endpoints;

public static class CoreEndpoints
{
    public static void MapConverterEndpoint(this WebApplication app)
    {
        static bool IsAllowedHost(Uri uri)
        {
            if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var host = uri.Host.ToLowerInvariant();
            string[] allowed =
            {
                // Amazon
                "amazon.com.br", "www.amazon.com.br", "amazon.com", "www.amazon.com", "amzn.to", "a.co",
                // Shopee
                "shopee.com", "www.shopee.com", "shopee.com.br", "www.shopee.com.br", "shope.ee",
                // Shein
                "shein.com", "www.shein.com", "shein.com.br", "www.shein.com.br",
                // Mercado Livre
                "mercadolivre.com.br", "www.mercadolivre.com.br", "mlb.cl", "mercadolivre.com",
                // URL Shorteners (will be expanded and re-validated internally)
                "tinyurl.com", "bit.ly", "cutt.ly", "shorturl.at", "ow.ly", "t.co", "rb.gy", "is.gd", "tiny.cc"
            };

            return allowed.Any(a => host.Equals(a, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + a, StringComparison.OrdinalIgnoreCase));
        }

        static async Task LogAttemptAsync(string logPath, object payload, CancellationToken ct)
        {
            try
            {
                var dir = Path.GetDirectoryName(logPath);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var json = JsonSerializer.Serialize(payload);
                await File.AppendAllTextAsync(logPath, json + Environment.NewLine, ct);
            }
            catch
            {
                // logging falhou — não bloquear fluxo do usuário
            }
        }

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
                return Results.Json(new { success = false, message = "forbidden" }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(payload.Text))
            {
                return Results.BadRequest(new { success = false, message = "Link vazio ou inválido." });
            }

            if (!Uri.TryCreate(payload.Text.Trim(), UriKind.Absolute, out var uri) || !IsAllowedHost(uri))
            {
                return Results.BadRequest(new { success = false, message = "Domínio não suportado para conversão." });
            }

            var result = await processor.ProcessAsync(payload.Text, payload.Source ?? "Webhook", ct);

            var response = new
            {
                success = result.Success,
                converted = result.ConvertedText,
                convertedLinks = result.ConvertedLinks,
                source = result.Source,
                message = result.Success
                    ? "Link convertido com sucesso."
                    : "Não foi possível converter esse link agora."
            };

            _ = LogAttemptAsync(
                Path.Combine(AppContext.BaseDirectory, "logs", "converter-public.log"),
                new
                {
                    ts = DateTimeOffset.UtcNow,
                    input = payload.Text,
                    source = payload.Source ?? "Webhook",
                    host = uri.Host.ToLowerInvariant(),
                    response.success,
                    response.message,
                    response.convertedLinks
                },
                ct);

            return Results.Ok(response);
        }).RequireRateLimiting("converter");
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
