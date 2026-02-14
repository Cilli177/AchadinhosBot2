using System.Collections.Concurrent;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.RegularExpressions;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramBotPollingService : BackgroundService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TelegramOptions _options;
    private readonly AffiliateOptions _affiliateOptions;
    private readonly IMessageProcessor _messageProcessor;
    private readonly ISettingsStore _settingsStore;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly IConversionLogStore _conversionLogStore;
    private readonly WebhookOptions _webhookOptions;
    private readonly IInstagramPostComposer _instagramComposer;
    private readonly InstagramConversationStore _instagramStore;
    private readonly ILogger<TelegramBotPollingService> _logger;
    private long _offset;
    private long? _botUserId;
    private string? _botUsername;
    private readonly ConcurrentDictionary<long, DateTimeOffset> _chatCooldown = new();
    private static readonly TimeSpan ChatCooldownWindow = TimeSpan.FromSeconds(1);

    public TelegramBotPollingService(
        IHttpClientFactory httpClientFactory,
        IOptions<TelegramOptions> options,
        IOptions<AffiliateOptions> affiliateOptions,
        IMessageProcessor messageProcessor,
        ISettingsStore settingsStore,
        ILinkTrackingStore linkTrackingStore,
        IConversionLogStore conversionLogStore,
        IOptions<WebhookOptions> webhookOptions,
        IInstagramPostComposer instagramComposer,
        InstagramConversationStore instagramStore,
        ILogger<TelegramBotPollingService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _affiliateOptions = affiliateOptions.Value;
        _messageProcessor = messageProcessor;
        _settingsStore = settingsStore;
        _linkTrackingStore = linkTrackingStore;
        _conversionLogStore = conversionLogStore;
        _webhookOptions = webhookOptions.Value;
        _instagramComposer = instagramComposer;
        _instagramStore = instagramStore;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_options.BotToken))
        {
            _logger.LogWarning("Telegram BotToken nÃ£o configurado. Polling nÃ£o iniciado.");
            return;
        }

        _logger.LogInformation("TelegramBotPollingService iniciado.");
        await DeleteWebhookAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_botUserId is null)
                {
                    _botUserId = await TryGetBotIdentityAsync(stoppingToken);
                }

                var updates = await GetUpdatesAsync(_offset, stoppingToken);
                foreach (var update in updates)
                {
                    _offset = Math.Max(_offset, update.UpdateId + 1);
                    await HandleUpdateAsync(update, stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no polling do Telegram");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private async Task<long?> TryGetBotIdentityAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var url = $"https://api.telegram.org/bot{_options.BotToken}/getMe";
            var res = await client.GetAsync(url, ct);
            if (!res.IsSuccessStatusCode)
            {
                _logger.LogWarning("Falha ao obter bot id: {Status}", res.StatusCode);
                return null;
            }

            var body = await res.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (!root.TryGetProperty("ok", out var okNode) || !okNode.GetBoolean())
            {
                return null;
            }

            if (!root.TryGetProperty("result", out var result))
            {
                return null;
            }

            var id = result.TryGetProperty("id", out var idNode) ? idNode.GetInt64() : (long?)null;
            _botUsername = GetString(result, "username");
            if (id is not null)
            {
                _logger.LogInformation("Bot identificado: {Id} @{Username}", id, _botUsername ?? "?");
            }

            return id;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao obter bot id");
            return null;
        }
    }

    private async Task DeleteWebhookAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var url = $"https://api.telegram.org/bot{_options.BotToken}/deleteWebhook?drop_pending_updates=true";
            var res = await client.GetAsync(url, ct);
            if (!res.IsSuccessStatusCode)
            {
                _logger.LogWarning("deleteWebhook falhou: {Status}", res.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao deletar webhook");
        }
    }

    private async Task<IReadOnlyList<TelegramUpdate>> GetUpdatesAsync(long offset, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("default");
        var url = $"https://api.telegram.org/bot{_options.BotToken}/getUpdates?offset={offset}&timeout=30";

        using var res = await client.GetAsync(url, ct);
        if (!res.IsSuccessStatusCode)
        {
            _logger.LogWarning("getUpdates falhou: {Status}", res.StatusCode);
            return Array.Empty<TelegramUpdate>();
        }

        var body = await res.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        if (!root.TryGetProperty("ok", out var okNode) || !okNode.GetBoolean())
        {
            return Array.Empty<TelegramUpdate>();
        }

        if (!root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<TelegramUpdate>();
        }

        var updates = new List<TelegramUpdate>();
        foreach (var updateNode in result.EnumerateArray())
        {
            if (TryExtractMessage(updateNode, out var update))
            {
                updates.Add(update);
            }
        }

        return updates;
    }

    private bool TryExtractMessage(JsonElement updateNode, out TelegramUpdate update)
    {
        update = new TelegramUpdate();
        if (!updateNode.TryGetProperty("update_id", out var updateId))
        {
            return false;
        }

        update.UpdateId = updateId.GetInt64();
        if (!updateNode.TryGetProperty("message", out var messageNode))
        {
            return false;
        }

        if (!messageNode.TryGetProperty("text", out var textNode) || textNode.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        if (!messageNode.TryGetProperty("chat", out var chatNode))
        {
            return false;
        }

        if (!chatNode.TryGetProperty("id", out var chatIdNode))
        {
            return false;
        }

        var msg = new TelegramMessage
        {
            ChatId = chatIdNode.GetInt64(),
            ChatType = GetString(chatNode, "type") ?? string.Empty,
            Text = textNode.GetString() ?? string.Empty
        };

        if (messageNode.TryGetProperty("from", out var fromNode) && fromNode.TryGetProperty("id", out var fromId))
        {
            msg.FromId = fromId.GetInt64();
        }

        update.Message = msg;
        return true;
    }

    private async Task HandleUpdateAsync(TelegramUpdate update, CancellationToken ct)
    {
        if (update.Message is null)
        {
            return;
        }

        if (_botUserId.HasValue && update.Message.FromId == _botUserId)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(update.Message.Text))
        {
            return;
        }

        if (IsRateLimited(update.Message.ChatId))
        {
            return;
        }

        var settings = await _settingsStore.GetAsync(ct);
        if (IsInstagramBotResponse(update.Message.Text))
        {
            return;
        }
        var instaSettings = settings.InstagramPosts;
        if (instaSettings.Enabled && instaSettings.AllowTelegramBot && IsTelegramInstagramAllowed(instaSettings, update.Message.ChatType))
        {
            if (instaSettings.TelegramChatIds.Count > 0 && !instaSettings.TelegramChatIds.Contains(update.Message.ChatId))
            {
                // ignore chats not explicitly allowed
            }
            else
            {
            var instaKey = $"tg:{update.Message.ChatId}";
            if (_instagramStore.TryConsume(instaKey, out var convo))
            {
                var post = await _instagramComposer.BuildAsync(update.Message.Text, convo.Context, instaSettings, ct);
                foreach (var chunk in SplitInstagramMessages(post))
                {
                    await SendMessageAsync(update.Message.ChatId, chunk, ct);
                }
                return;
            }

            if (IsInstagramTrigger(update.Message.Text, instaSettings.Triggers))
            {
                if (TryGetInstagramInlineProduct(update.Message.Text, instaSettings.Triggers, out var inlineProduct))
                {
                    var post = await _instagramComposer.BuildAsync(inlineProduct, null, instaSettings, ct);
                    foreach (var chunk in SplitInstagramMessages(post))
                    {
                        await SendMessageAsync(update.Message.ChatId, chunk, ct);
                    }
                }
                else
                {
                    _instagramStore.SetPending(instaKey, update.Message.Text);
                    await SendMessageAsync(update.Message.ChatId, "Qual produto? Envie o nome ou o link.", ct);
                }
                return;
            }
            }
        }

        var autoReply = GetAutoReply(settings, update.Message.Text);
        if (!string.IsNullOrWhiteSpace(autoReply))
        {
            var trackedReply = await ApplyTrackingAsync(autoReply, settings.LinkResponder?.TrackingEnabled ?? true, ct);
            await SendMessageAsync(update.Message.ChatId, trackedReply.Text, ct);
            _ = _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
            {
                Source = "AutoReply",
                Store = "AutoReply",
                Success = true,
                OriginalUrl = update.Message.Text,
                ConvertedUrl = trackedReply.Text,
                TrackingIds = trackedReply.TrackingIds,
                OriginChatId = update.Message.ChatId,
                DestinationChatId = update.Message.ChatId
            }, ct);
            return;
        }

        if (!update.Message.Text.Contains("http", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var responder = settings.LinkResponder;
        if (!responder.Enabled || !responder.AllowTelegramBot)
        {
            return;
        }

        if (!IsTelegramResponderAllowed(responder, update.Message.ChatId, update.Message.ChatType))
        {
            return;
        }

        var result = await _messageProcessor.ProcessAsync(
            update.Message.Text,
            "TelegramResponder",
            ct,
            originChatId: update.Message.ChatId,
            destinationChatId: update.Message.ChatId);
        if (!result.Success || string.IsNullOrWhiteSpace(result.ConvertedText))
        {
            if (!IsTelegramGroupChat(update.Message.ChatType) && !string.IsNullOrWhiteSpace(responder.ReplyOnFailure))
            {
                await SendMessageAsync(update.Message.ChatId, responder.ReplyOnFailure, ct);
            }
            return;
        }

        var response = BuildResponderMessage(responder, result.ConvertedText);
        if (responder.AppendSheinCode &&
            response.Contains("shein", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(_affiliateOptions.SheinCode) &&
            !response.Contains(_affiliateOptions.SheinCode, StringComparison.OrdinalIgnoreCase))
        {
            response += $"\n\nCodigo Shein: {_affiliateOptions.SheinCode}";
        }

        if (!string.IsNullOrWhiteSpace(responder.FooterText))
        {
            response += $"\n\n{responder.FooterText}";
        }

        var trackedResponse = await ApplyTrackingAsync(response, responder.TrackingEnabled, ct);
        response = trackedResponse.Text;
        await SendMessageAsync(update.Message.ChatId, response, ct);
        _ = _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
        {
            Source = "TelegramResponder",
            Store = "Unknown",
            Success = true,
            OriginalUrl = update.Message.Text,
            ConvertedUrl = response,
            TrackingIds = trackedResponse.TrackingIds,
            OriginChatId = update.Message.ChatId,
            DestinationChatId = update.Message.ChatId
        }, ct);
    }

    private bool IsRateLimited(long chatId)
    {
        var now = DateTimeOffset.UtcNow;
        if (_chatCooldown.TryGetValue(chatId, out var last) && now - last < ChatCooldownWindow)
        {
            return true;
        }

        _chatCooldown[chatId] = now;
        return false;
    }

    private static string? GetAutoReply(AutomationSettings settings, string text)
    {
        if (!settings.AutoRepliesSettings.Enabled) return null;
        if (string.IsNullOrWhiteSpace(text)) return null;
        var hasLink = text.Contains("http", StringComparison.OrdinalIgnoreCase);
        if (hasLink) return null;

        foreach (var rule in settings.AutoReplies)
        {
            if (!rule.Enabled) continue;
            if (string.IsNullOrWhiteSpace(rule.Trigger)) continue;
            if (text.Contains(rule.Trigger, StringComparison.OrdinalIgnoreCase))
            {
                return rule.ResponseTemplate;
            }
        }

        return null;
    }

    private static bool IsInstagramTrigger(string text, List<string> triggers)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (triggers is null || triggers.Count == 0) return false;
        foreach (var trigger in triggers)
        {
            if (string.IsNullOrWhiteSpace(trigger)) continue;
            if (text.Contains(trigger, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsInstagramBotResponse(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        return text.Contains("POST PARA INSTAGRAM", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Legenda 1", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase)
               || text.StartsWith("Qual produto?", StringComparison.OrdinalIgnoreCase)
               || text.Contains("Envie o nome ou o link", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> SplitInstagramMessages(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            yield break;
        }

        var lines = text.Replace("\r", string.Empty).Split('\n');
        var blocks = new List<List<string>>();

        foreach (var raw in lines)
        {
            var line = raw?.TrimEnd() ?? string.Empty;
            if (IsInstagramSectionHeader(line) && blocks.Count > 0)
            {
                blocks.Add(new List<string>());
            }
            if (blocks.Count == 0)
            {
                blocks.Add(new List<string>());
            }
            blocks[^1].Add(line);
        }

        foreach (var block in blocks)
        {
            var chunk = string.Join('\n', block).Trim();
            if (!string.IsNullOrWhiteSpace(chunk))
            {
                yield return chunk;
            }
        }
    }

    private static bool IsInstagramSectionHeader(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return false;
        var t = line.Trim();
        return t.StartsWith("Legenda 1", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Legenda 2", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestões de imagem", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestoes de imagem", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Post extra", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestão rápida", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Sugestao rapida", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetInstagramInlineProduct(string text, List<string> triggers, out string product)
    {
        product = string.Empty;
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (triggers is null || triggers.Count == 0) return false;
        var normalized = text.Trim();
        foreach (var trigger in triggers)
        {
            if (string.IsNullOrWhiteSpace(trigger)) continue;
            var idx = normalized.IndexOf(trigger, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var remaining = normalized.Remove(idx, trigger.Length).Trim();
            remaining = remaining.Trim('-', ':', '—', '–');
            if (!string.IsNullOrWhiteSpace(remaining))
            {
                product = remaining;
                return true;
            }
        }
        return false;
    }

    private static bool IsTelegramInstagramAllowed(InstagramPostSettings settings, string? chatType)
    {
        if (settings.TelegramChatIds.Count > 0)
        {
            // For bot updates, we cannot map chatType to id here; the caller already has chatId.
            // This method is kept for compatibility; chatId filtering is handled earlier.
        }
        return IsTelegramGroupChat(chatType) ? settings.TelegramAllowGroups : settings.TelegramAllowPrivate;
    }

    private static bool IsTelegramResponderAllowed(LinkResponderSettings responder, long chatId, string? chatType)
    {
        if (responder.TelegramChatIds.Count > 0)
        {
            return responder.TelegramChatIds.Contains(chatId);
        }

        return IsTelegramGroupChat(chatType) ? responder.TelegramAllowGroups : responder.TelegramAllowPrivate;
    }

    private static bool IsTelegramGroupChat(string? chatType)
        => string.Equals(chatType, "group", StringComparison.OrdinalIgnoreCase)
           || string.Equals(chatType, "supergroup", StringComparison.OrdinalIgnoreCase)
           || string.Equals(chatType, "channel", StringComparison.OrdinalIgnoreCase);

    private static string BuildResponderMessage(LinkResponderSettings responder, string convertedText)
    {
        var template = responder.ReplyTemplate;
        if (string.IsNullOrWhiteSpace(template))
        {
            return convertedText;
        }

        var result = template;
        if (result.Contains("{link}", StringComparison.OrdinalIgnoreCase))
        {
            result = result.Replace("{link}", convertedText, StringComparison.OrdinalIgnoreCase);
        }

        if (result.Contains("{text}", StringComparison.OrdinalIgnoreCase))
        {
            result = result.Replace("{text}", convertedText, StringComparison.OrdinalIgnoreCase);
        }

        if (!result.Contains(convertedText, StringComparison.OrdinalIgnoreCase))
        {
            result = $"{result}\n{convertedText}";
        }

        return result;
    }

    private async Task<TrackingResult> ApplyTrackingAsync(string text, bool trackingEnabled, CancellationToken ct)
    {
        if (!trackingEnabled || string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(_webhookOptions.PublicBaseUrl))
        {
            return new TrackingResult(text, new List<string>());
        }

        var baseUrl = _webhookOptions.PublicBaseUrl.TrimEnd('/');
        var trackingSuffix = GetTrackingSuffix(baseUrl);
        var matches = UrlRegex.Matches(text);
        if (matches.Count == 0) return new TrackingResult(text, new List<string>());

        var sb = new StringBuilder(text.Length + 32);
        var lastIndex = 0;
        var trackingIds = new List<string>();
        foreach (Match match in matches)
        {
            sb.Append(text, lastIndex, match.Index - lastIndex);
            var url = match.Value;
            if (url.StartsWith(baseUrl, StringComparison.OrdinalIgnoreCase))
            {
                sb.Append(url);
            }
            else
            {
                var entry = await _linkTrackingStore.CreateAsync(url, ct);
                sb.Append($"{baseUrl}/r/{entry.Id}{trackingSuffix}");
                trackingIds.Add(entry.Id);
            }
            lastIndex = match.Index + match.Length;
        }
        sb.Append(text, lastIndex, text.Length - lastIndex);
        return new TrackingResult(sb.ToString(), trackingIds);
    }

    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private sealed record TrackingResult(string Text, List<string> TrackingIds);

    private static string GetTrackingSuffix(string baseUrl)
    {
        var lower = baseUrl.ToLowerInvariant();
        if (lower.Contains("ngrok-free") || lower.Contains("ngrok.app"))
        {
            return "?ngrok-skip-browser-warning=1";
        }
        return string.Empty;
    }

    private async Task SendMessageAsync(long chatId, string text, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("default");
        var url = $"https://api.telegram.org/bot{_options.BotToken}/sendMessage";
        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        var payload = JsonSerializer.Serialize(new
        {
            chat_id = chatId,
            text
        });
        req.Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");

        var res = await client.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var body = await res.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("Falha ao responder Telegram: {Status} {Body}", res.StatusCode, body);
            return;
        }

        _ = await res.Content.ReadAsStringAsync(ct);
    }

    private static string? GetString(JsonElement node, string property)
        => node.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static HashSet<string> DetectStores(string text)
    {
        var stores = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var lower = text.ToLowerInvariant();
        if (lower.Contains("amazon.") || lower.Contains("amzn.to") || lower.Contains("a.co"))
        {
            stores.Add("Amazon");
        }
        if (lower.Contains("mercadolivre") || lower.Contains("mercadolibre"))
        {
            stores.Add("Mercado Livre");
        }
        if (lower.Contains("shopee") || lower.Contains("shope.ee") || lower.Contains("s.shopee"))
        {
            stores.Add("Shopee");
        }
        if (lower.Contains("shein"))
        {
            stores.Add("Shein");
        }

        return stores;
    }

    private sealed class TelegramUpdate
    {
        public long UpdateId { get; set; }
        public TelegramMessage? Message { get; set; }
    }

    private sealed class TelegramMessage
    {
        public long ChatId { get; set; }
        public long? FromId { get; set; }
        public string Text { get; set; } = string.Empty;
        public string ChatType { get; set; } = string.Empty;
    }
}
