using System.Text.Json;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

/// <summary>
/// Converts Evolution webhook payloads into the application message contract.
/// Malformed or unsupported payloads deliberately produce no messages, so a
/// webhook delivery cannot interrupt the receiving endpoint.
/// </summary>
public static class EvolutionIncomingMessageExtractor
{
    public static IReadOnlyList<WhatsAppIncomingMessage> Extract(string body)
    {
        var items = new List<WhatsAppIncomingMessage>();
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var instanceName = GetString(root, "instance");
            var data = root.TryGetProperty("data", out var dataNode) ? dataNode : root;

            if (data.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in data.EnumerateArray()) AddIfMessage(items, item, instanceName);
                return items;
            }

            if (data.TryGetProperty("messages", out var messagesNode) && messagesNode.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in messagesNode.EnumerateArray()) AddIfMessage(items, item, instanceName);
                return items;
            }

            if (TryExtract(data, instanceName, out var single))
            {
                items.Add(single);
                return items;
            }

            AddIfMessage(items, root, instanceName);
        }
        catch (JsonException)
        {
            // Invalid third-party payload: acknowledge the webhook without processing it.
        }

        return items;
    }

    private static void AddIfMessage(List<WhatsAppIncomingMessage> items, JsonElement node, string? instanceName)
    {
        if (TryExtract(node, instanceName, out var message)) items.Add(message);
    }

    private static bool TryExtract(JsonElement node, string? instanceName, out WhatsAppIncomingMessage message)
    {
        message = new WhatsAppIncomingMessage(string.Empty, null, string.Empty, false, instanceName, null, false, null, null, null, null, null);
        var chatId = string.Empty;
        var senderId = string.Empty;
        var messageId = string.Empty;
        var fromMe = false;

        if (node.TryGetProperty("key", out var key))
        {
            chatId = GetString(key, "remoteJid") ?? string.Empty;
            senderId = GetString(key, "participant", "sender", "from") ?? string.Empty;
            messageId = GetString(key, "id") ?? string.Empty;
            fromMe = GetBool(key, "fromMe");
        }

        chatId = string.IsNullOrWhiteSpace(chatId) ? GetString(node, "remoteJid", "chatId", "from", "to") ?? string.Empty : chatId;
        fromMe |= GetBool(node, "fromMe");
        senderId = string.IsNullOrWhiteSpace(senderId) ? GetString(node, "participant", "sender", "sender_id", "from") ?? string.Empty : senderId;
        if (string.IsNullOrWhiteSpace(senderId) && node.TryGetProperty("sender", out var senderNode))
        {
            senderId = senderNode.ValueKind == JsonValueKind.String
                ? senderNode.GetString() ?? string.Empty
                : senderNode.ValueKind == JsonValueKind.Object ? GetString(senderNode, "id", "jid", "from", "user") ?? string.Empty : string.Empty;
        }
        if (string.IsNullOrWhiteSpace(senderId) && fromMe) senderId = "self";

        var text = ExtractText(node);
        var hasMedia = TryExtractMedia(node, out var mediaUrl, out var mediaBase64, out var mediaMimeType, out var mediaFileName);
        if (string.IsNullOrWhiteSpace(text) && !hasMedia) return false;

        message = new WhatsAppIncomingMessage(chatId, string.IsNullOrWhiteSpace(senderId) ? null : senderId, text, fromMe,
            instanceName, string.IsNullOrWhiteSpace(messageId) ? null : messageId, hasMedia, mediaUrl, mediaBase64,
            mediaMimeType, mediaFileName, node.GetRawText());
        return true;
    }

    private static bool TryExtractMedia(JsonElement node, out string? mediaUrl, out string? mediaBase64, out string? mediaMimeType, out string? mediaFileName)
    {
        mediaUrl = mediaBase64 = mediaMimeType = mediaFileName = null;
        var hasMedia = false;
        var messageNode = node.TryGetProperty("message", out var rootMessage) ? rootMessage : node;
        while (TryUnwrapEnvelope(messageNode, out var inner)) messageNode = inner;
        if (TryGetMediaNode(messageNode, out var mediaNode))
        {
            hasMedia = true;
            mediaUrl = GetString(mediaNode, "url", "mediaUrl", "media_url");
            mediaBase64 = GetString(mediaNode, "base64", "fileBase64", "data");
            mediaMimeType = GetString(mediaNode, "mimetype", "mimeType");
            mediaFileName = GetString(mediaNode, "fileName", "filename");
        }
        mediaUrl ??= GetString(node, "mediaUrl", "media_url");
        mediaBase64 ??= GetString(node, "base64", "fileBase64");
        mediaMimeType ??= GetString(node, "mimetype", "mimeType");
        mediaFileName ??= GetString(node, "fileName", "filename");
        mediaUrl ??= GetString(messageNode, "mediaUrl", "media_url", "url");
        mediaBase64 ??= GetString(messageNode, "base64", "fileBase64", "data");
        mediaMimeType ??= GetString(messageNode, "mimetype", "mimeType");
        mediaFileName ??= GetString(messageNode, "fileName", "filename");

        if (string.IsNullOrWhiteSpace(mediaBase64) && !string.IsNullOrWhiteSpace(mediaUrl) && mediaUrl.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            var comma = mediaUrl.IndexOf(',');
            if (comma > 0 && comma + 1 < mediaUrl.Length)
            {
                var header = mediaUrl[..comma];
                if (string.IsNullOrWhiteSpace(mediaMimeType) && header.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    var semicolon = header.IndexOf(';');
                    if (semicolon > 5) mediaMimeType = header[5..semicolon];
                }
                mediaBase64 = mediaUrl[(comma + 1)..];
                mediaUrl = null;
            }
        }
        if (!hasMedia)
        {
            var type = GetString(node, "messageType", "type");
            hasMedia = !string.IsNullOrWhiteSpace(type) && (type.Contains("image", StringComparison.OrdinalIgnoreCase) || type.Contains("media", StringComparison.OrdinalIgnoreCase));
        }
        return hasMedia || !string.IsNullOrWhiteSpace(mediaUrl) || !string.IsNullOrWhiteSpace(mediaBase64);
    }

    private static string ExtractText(JsonElement node)
    {
        var messageNode = node.TryGetProperty("message", out var rootMessage) ? rootMessage : node;
        while (TryUnwrapEnvelope(messageNode, out var innerMessage)) messageNode = innerMessage;

        var conversation = GetString(messageNode, "conversation", "text", "body");
        if (!string.IsNullOrWhiteSpace(conversation)) return conversation;
        if (messageNode.TryGetProperty("extendedTextMessage", out var extended) && GetString(extended, "text") is { } extendedText) return extendedText;
        foreach (var property in new[] { "imageMessage", "videoMessage", "documentMessage" })
            if (messageNode.TryGetProperty(property, out var media) && GetString(media, "caption") is { } caption && !string.IsNullOrWhiteSpace(caption)) return caption;

        return GetString(node, "text", "body") ?? string.Empty;
    }

    private static bool TryGetMediaNode(JsonElement node, out JsonElement mediaNode)
    {
        foreach (var property in new[] { "imageMessage", "videoMessage", "documentMessage", "stickerMessage" })
            if (node.TryGetProperty(property, out mediaNode)) return true;
        mediaNode = default;
        return false;
    }

    private static bool TryUnwrapEnvelope(JsonElement node, out JsonElement inner)
    {
        foreach (var property in new[] { "ephemeralMessage", "viewOnceMessage", "viewOnceMessageV2", "viewOnceMessageV2Extension", "editedMessage" })
            if (node.TryGetProperty(property, out var envelope) && envelope.TryGetProperty("message", out inner)) return true;
        inner = default;
        return false;
    }

    private static string? GetString(JsonElement node, params string[] names)
    {
        foreach (var name in names)
            if (node.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String) return value.GetString();
        return null;
    }

    private static bool GetBool(JsonElement node, string name)
        => node.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
}
