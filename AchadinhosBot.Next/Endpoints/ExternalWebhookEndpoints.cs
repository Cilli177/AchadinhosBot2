using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Infrastructure.WhatsApp;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

public static class ExternalWebhookEndpoints
{
    public static void MapExternalWebhookEndpoints(this WebApplication app)
    {
        app.MapPost("/webhooks/evolution", async (
            HttpRequest request,
            IOptions<EvolutionOptions> evolution,
            IOptions<WebhookOptions> webhookOptions,
            IIdempotencyStore idempotency,
            ISettingsStore settingsStore,
            IWhatsAppGroupMembershipStore membershipStore,
            IAuditTrail audit,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("ExternalWebhookEndpoints");
            var body = await new StreamReader(request.Body).ReadToEndAsync(ct);
            if (!WebhookRequestAuthorizer.IsAuthorized(request, body, evolution.Value.WebhookSecret, webhookOptions.Value.ApiKey))
            {
                return Results.Unauthorized();
            }

            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var eventName = root.TryGetProperty("event", out var eventNode) ? eventNode.GetString() : "unknown";

            if (string.Equals(eventName, "group-participants.update", StringComparison.OrdinalIgnoreCase))
            {
                await StoreMonitoredMembershipEventsAsync(root, settingsStore, membershipStore, logger, ct);
            }

            var eventId = root.TryGetProperty("eventId", out var eventIdNode) ? eventIdNode.GetString() : null;
            var idempotencyKey = $"evolution:{eventName}:{eventId ?? body.GetHashCode().ToString()}";
            if (!idempotency.TryBegin(idempotencyKey, TimeSpan.FromHours(6)))
            {
                return Results.Ok(new { success = true, duplicate = true });
            }

            var settings = await settingsStore.GetAsync(ct);
            if (string.Equals(eventName, "connection.update", StringComparison.OrdinalIgnoreCase) && root.TryGetProperty("data", out var data))
            {
                var state = data.TryGetProperty("state", out var stateNode) ? stateNode.GetString() : null;
                if (string.Equals(state, "open", StringComparison.OrdinalIgnoreCase))
                {
                    settings.Integrations.WhatsApp.Connected = true;
                    settings.Integrations.WhatsApp.LastLoginAt = DateTimeOffset.UtcNow;
                    settings.Integrations.WhatsApp.Notes = "Conectado via webhook Evolution";
                }
                else if (string.Equals(state, "close", StringComparison.OrdinalIgnoreCase))
                {
                    settings.Integrations.WhatsApp.Connected = false;
                    settings.Integrations.WhatsApp.Notes = "Desconectado via webhook Evolution";
                }

                await settingsStore.SaveAsync(settings, ct);
            }

            await audit.WriteAsync("evolution.webhook.received", "system", new { eventName, eventId }, ct);
            return Results.Ok(new { success = true });
        });

        app.MapPost("/webhook/bot-conversor", async (
            HttpRequest request,
            IMessageOrchestrator orchestrator,
            IWhatsAppGroupMembershipStore membershipStore,
            ISettingsStore settingsStore,
            ILoggerFactory loggerFactory,
            IOptions<EvolutionOptions> evolutionOptions,
            IOptions<WebhookOptions> webhookOptions,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("ExternalWebhookEndpoints");
            request.EnableBuffering();
            var body = await new StreamReader(request.Body).ReadToEndAsync(ct);
            request.Body.Position = 0;

            if (!WebhookRequestAuthorizer.IsAuthorized(request, body, evolutionOptions.Value.WebhookSecret, webhookOptions.Value.ApiKey))
            {
                return Results.Unauthorized();
            }

            if (string.IsNullOrWhiteSpace(body))
            {
                return Results.Ok(new { success = true, ignored = true });
            }

            var headers = request.Headers.ToDictionary(header => header.Key, header => header.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            var result = await orchestrator.EnqueueBotConversorAsync(body, headers, ct);

            try
            {
                var membershipEvents = EvolutionMembershipEventParser.Extract(body);
                if (membershipEvents.Count > 0)
                {
                    var monitoredGroupIds = new HashSet<string>((await settingsStore.GetAsync(ct)).MonitoredGroupIds ?? [], StringComparer.OrdinalIgnoreCase);
                    foreach (var membershipEvent in membershipEvents.Where(x => monitoredGroupIds.Contains(x.GroupId)))
                    {
                        await membershipStore.AppendAsync(membershipEvent, ct);
                    }

                    logger.LogInformation("Registrados {Count} eventos de membership via webhook principal.", membershipEvents.Count(x => monitoredGroupIds.Contains(x.GroupId)));
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Falha ao processar membership events no webhook principal.");
            }

            if (!result.Accepted)
            {
                logger.LogWarning("Webhook bot-conversor falhou ao enfileirar. MessageId={MessageId} Mode={Mode} Error={Error}", result.MessageId, result.Mode, result.Error);
                return Results.StatusCode(StatusCodes.Status502BadGateway);
            }

            return Results.Ok(new { success = true, messageId = result.MessageId, mode = result.Mode, persistedLocally = result.PersistedLocally });
        });
    }

    private static async Task StoreMonitoredMembershipEventsAsync(
        JsonElement root,
        ISettingsStore settingsStore,
        IWhatsAppGroupMembershipStore membershipStore,
        ILogger logger,
        CancellationToken ct)
    {
        try
        {
            var settings = await settingsStore.GetAsync(ct);
            var data = root.GetProperty("data");
            var groupId = data.TryGetProperty("id", out var groupIdNode) ? groupIdNode.GetString() : null;
            if (string.IsNullOrWhiteSpace(groupId) || !settings.MonitoredGroupIds.Contains(groupId, StringComparer.OrdinalIgnoreCase))
            {
                return;
            }

            var action = data.TryGetProperty("action", out var actionNode) ? actionNode.GetString() : null;
            if (!data.TryGetProperty("participants", out var participants) || participants.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var participant in participants.EnumerateArray())
            {
                var participantId = participant.ValueKind == JsonValueKind.String
                    ? participant.GetString()
                    : GetString(participant, "phoneNumber", "id", "jid", "participant", "user");
                if (!string.IsNullOrWhiteSpace(participantId))
                {
                    await membershipStore.AppendAsync(new WhatsAppGroupMembershipEvent
                    {
                        GroupId = groupId,
                        ParticipantId = participantId,
                        Action = action ?? "unknown",
                        Timestamp = DateTimeOffset.UtcNow
                    }, ct);
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro ao processar group-participants.update no webhook (Evolution).");
        }
    }

    private static string? GetString(JsonElement node, params string[] names)
    {
        foreach (var name in names)
        {
            if (node.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }
        }

        return null;
    }
}
