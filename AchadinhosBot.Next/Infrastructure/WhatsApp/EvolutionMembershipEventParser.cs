using System.Text.Json;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public static class EvolutionMembershipEventParser
{
    public static IReadOnlyList<WhatsAppGroupMembershipEvent> Extract(string body)
    {
        var events = new List<WhatsAppGroupMembershipEvent>();
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;

            if (!root.TryGetProperty("event", out var eventNode) || eventNode.ValueKind != JsonValueKind.String)
            {
                var data = root.TryGetProperty("data", out var dataNode) ? dataNode : root;
                if (!data.TryGetProperty("action", out _) || !data.TryGetProperty("participants", out _))
                {
                    return events;
                }
            }
            else
            {
                var eventName = eventNode.GetString();
                if (!string.Equals(eventName, "group.participants.update", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(eventName, "group_participants_update", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(eventName, "group-participants.update", StringComparison.OrdinalIgnoreCase))
                {
                    return events;
                }
            }

            var payload = root.TryGetProperty("data", out var payloadNode) ? payloadNode : root;
            var groupId = GetString(payload, "id", "groupId", "groupJid", "jid");
            var action = GetString(payload, "action", "updateType");
            if (string.IsNullOrWhiteSpace(groupId) || string.IsNullOrWhiteSpace(action) ||
                !payload.TryGetProperty("participants", out var participants) || participants.ValueKind != JsonValueKind.Array)
            {
                return events;
            }

            foreach (var participant in participants.EnumerateArray())
            {
                var participantId = participant.ValueKind == JsonValueKind.String
                    ? participant.GetString()
                    : GetString(participant, "phoneNumber", "id", "jid", "participant", "user");
                if (!string.IsNullOrWhiteSpace(participantId))
                {
                    events.Add(new WhatsAppGroupMembershipEvent
                    {
                        GroupId = groupId,
                        GroupName = "Evolution Webhook",
                        ParticipantId = participantId,
                        Action = action,
                        Timestamp = DateTimeOffset.UtcNow,
                        IsSyncDetection = false
                    });
                }
            }
        }
        catch
        {
            // A webhook malformed must not interrupt the primary message path.
        }

        return events;
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
