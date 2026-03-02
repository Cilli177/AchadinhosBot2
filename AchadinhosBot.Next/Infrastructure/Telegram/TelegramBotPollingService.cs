using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
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
    private readonly IInstagramAutoPilotService _instagramAutoPilotService;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly InstagramLinkMetaService _instagramMeta;
    private readonly WebhookOptions _webhookOptions;
    private readonly IInstagramPostComposer _instagramComposer;
    private readonly InstagramConversationStore _instagramStore;
    private readonly ILogger<TelegramBotPollingService> _logger;
    private long _offset;
    private long? _botUserId;
    private string? _botUsername;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private readonly ConcurrentDictionary<long, DateTimeOffset> _chatCooldown = new();
    private readonly ConcurrentDictionary<long, List<AssistantMessage>> _assistantHistory = new();
    private static readonly TimeSpan ChatCooldownWindow = TimeSpan.FromSeconds(1);
    private const int AssistantHistoryMaxMessages = 12;

    public TelegramBotPollingService(
        IHttpClientFactory httpClientFactory,
        IOptions<TelegramOptions> options,
        IOptions<AffiliateOptions> affiliateOptions,
        IMessageProcessor messageProcessor,
        ISettingsStore settingsStore,
        ILinkTrackingStore linkTrackingStore,
        IConversionLogStore conversionLogStore,
        IInstagramAutoPilotService instagramAutoPilotService,
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        InstagramLinkMetaService instagramMeta,
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
        _instagramAutoPilotService = instagramAutoPilotService;
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _instagramMeta = instagramMeta;
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
        if (TryParseBotCommand(update.Message.Text, _botUsername, out var botCommand))
        {
            await HandleBotCommandAsync(update.Message, botCommand, settings, ct);
            return;
        }
        if (TryParseConversationalCommand(update.Message.Text, out var conversationalCommand))
        {
            await HandleBotCommandAsync(update.Message, conversationalCommand, settings, ct);
            return;
        }
        if (TryNormalizeConversationalInput(update.Message.Text, out var conversationalInput))
        {
            if (!IsBotCommandAuthorized(update.Message.ChatId, settings))
            {
                await SendMessageAsync(update.Message.ChatId, "Este chat nao esta autorizado para comandos de automacao.", ct);
                return;
            }

            var aiCommand = await TryResolveAssistantCommandAsync(conversationalInput, settings, ct);
            if (aiCommand is not null)
            {
                await HandleBotCommandAsync(update.Message, aiCommand, settings, ct);
                return;
            }

            var aiReply = await TryGenerateAssistantReplyAsync(update.Message.ChatId, conversationalInput, settings, ct);
            if (!string.IsNullOrWhiteSpace(aiReply))
            {
                foreach (var chunk in SplitLongMessages(aiReply, 3500))
                {
                    await SendMessageAsync(update.Message.ChatId, chunk, ct);
                }
            }
            else
            {
                await SendMessageAsync(
                    update.Message.ChatId,
                    "Recebi sua mensagem, mas nao consegui responder com IA agora.\nUse /help para comandos ou ajuste as chaves OpenAI/Gemini.",
                    ct);
            }
            return;
        }

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

    private async Task HandleBotCommandAsync(TelegramMessage message, TelegramBotCommand command, AutomationSettings settings, CancellationToken ct)
    {
        if (!IsBotCommandAuthorized(message.ChatId, settings))
        {
            await SendMessageAsync(message.ChatId, "Este chat nao esta autorizado para comandos de automacao.", ct);
            return;
        }

        switch (command.Name)
        {
            case "start":
            case "help":
                await SendMessageAsync(message.ChatId, BuildHelpMessage(message.ChatId), ct);
                return;

            case "chatid":
                await SendMessageAsync(message.ChatId, $"Chat ID: {message.ChatId}", ct);
                return;

            case "ping":
                await SendMessageAsync(message.ChatId, "pong", ct);
                return;

            case "status":
                await SendMessageAsync(message.ChatId, BuildStatusMessage(settings), ct);
                return;

            case "assist":
            case "ai":
            case "ask":
            case "codex":
            case "assistente":
            {
                var prompt = string.Join(' ', command.Arguments).Trim();
                if (string.IsNullOrWhiteSpace(prompt))
                {
                    await SendMessageAsync(message.ChatId, "Uso: /assist <mensagem>\nEx.: /assist remove as imagens 1,3 e 5 do draft 2", ct);
                    return;
                }

                var aiReply = await TryGenerateAssistantReplyAsync(message.ChatId, prompt, settings, ct);
                if (string.IsNullOrWhiteSpace(aiReply))
                {
                    await SendMessageAsync(message.ChatId, "Nao consegui responder com IA agora. Verifique chaves OpenAI/Gemini e tente novamente.", ct);
                    return;
                }

                foreach (var chunk in SplitLongMessages(aiReply, 3500))
                {
                    await SendMessageAsync(message.ChatId, chunk, ct);
                }
                return;
            }

            case "assistclear":
            case "clearassist":
            case "limparamemoria":
            case "limparcontexto":
            {
                _assistantHistory.TryRemove(message.ChatId, out _);
                await SendMessageAsync(message.ChatId, "Contexto da conversa com IA foi limpo para este chat.", ct);
                return;
            }

            case "lista":
            case "listar":
            case "list":
            case "drafts":
            case "rascunhos":
            {
                var limit = 8;
                if (command.Arguments.Length > 0 && int.TryParse(command.Arguments[0], out var parsedLimit))
                {
                    limit = Math.Clamp(parsedLimit, 1, 20);
                }

                await SendMessageAsync(message.ChatId, await BuildDraftListMessageAsync(limit, ct), ct);
                return;
            }

            case "draft":
            case "revisar":
            case "review":
            case "ver":
            {
                var draftRef = command.Arguments.FirstOrDefault();
                var (draft, error) = await ResolveDraftAsync(draftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }

                await SendMessageAsync(message.ChatId, BuildDraftReviewMessage(draft), ct);
                return;
            }

            case "aprovar":
            case "approve":
            case "confirmar":
            {
                var draftRef = command.Arguments.FirstOrDefault();
                var (draft, error) = await ResolveDraftAsync(draftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }

                draft.Status = "approved";
                draft.Error = null;
                await _publishStore.UpdateAsync(draft, ct);
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "tg_draft_approved",
                    Success = true,
                    DraftId = draft.Id,
                    Details = $"Chat={message.ChatId}"
                }, ct);

                var shortId = ShortDraftId(draft.Id);
                await SendMessageAsync(
                    message.ChatId,
                    $"Draft {shortId} aprovado para publicacao.\nStatus: approved\nDica: revise imagem/legenda com /revisar {shortId}.",
                    ct);
                return;
            }

            case "reprovar":
            case "reject":
            {
                var parsed = ParseDraftTextArguments(command.Arguments);
                var (draft, error) = await ResolveDraftAsync(parsed.DraftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }

                var reason = string.IsNullOrWhiteSpace(parsed.Text) ? "Reprovado via bot." : parsed.Text.Trim();
                draft.Status = "rejected";
                draft.Error = reason;
                await _publishStore.UpdateAsync(draft, ct);
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "tg_draft_rejected",
                    Success = true,
                    DraftId = draft.Id,
                    Error = reason,
                    Details = $"Chat={message.ChatId}"
                }, ct);

                await SendMessageAsync(message.ChatId, $"Draft {ShortDraftId(draft.Id)} reprovado.\nMotivo: {reason}", ct);
                return;
            }

            case "trocarimg":
            case "trocarimagem":
            case "trocar-imagem":
            {
                var draftRef = command.Arguments.FirstOrDefault();
                var (draft, error) = await ResolveDraftAsync(draftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }

                var replaceResult = await ReplaceDraftImageAsync(draft, message.ChatId, ct);
                await SendMessageAsync(message.ChatId, replaceResult, ct);
                return;
            }

            case "img":
            case "imagem":
            {
                var parsed = ParseImageCommandArguments(command.Arguments);
                var (draft, error) = await ResolveDraftAsync(parsed.DraftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }

                if (parsed.Indexes.Count == 0)
                {
                    await SendMessageAsync(message.ChatId, BuildDraftImageListMessage(draft), ct);
                    return;
                }

                var max = draft.ImageUrls?.Count ?? 0;
                if (max == 0)
                {
                    await SendMessageAsync(message.ChatId, $"Draft {ShortDraftId(draft.Id)} sem imagens. Use /trocarimg {ShortDraftId(draft.Id)}.", ct);
                    return;
                }

                var selected = parsed.Indexes.Where(i => i >= 1 && i <= max).Distinct().OrderBy(i => i).ToList();
                if (selected.Count == 0)
                {
                    await SendMessageAsync(message.ChatId, $"Indice invalido. Use valores entre 1 e {max}.", ct);
                    return;
                }

                draft.SelectedImageIndexes = selected;
                draft.Status = "draft";
                draft.Error = null;
                await _publishStore.UpdateAsync(draft, ct);
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "tg_draft_select_images",
                    Success = true,
                    DraftId = draft.Id,
                    Details = $"Indexes={string.Join(",", selected)};Chat={message.ChatId}"
                }, ct);

                await SendMessageAsync(
                    message.ChatId,
                    $"Imagem(ns) selecionada(s) no draft {ShortDraftId(draft.Id)}: {string.Join(", ", selected)}.\nUse /revisar {ShortDraftId(draft.Id)} para validar.",
                    ct);
                return;
            }

            case "removerimg":
            case "removerimagem":
            case "removeimg":
            case "rmimg":
            {
                var parsed = ParseImageCommandArguments(command.Arguments);
                var (draft, error) = await ResolveDraftAsync(parsed.DraftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }

                if (parsed.Indexes.Count == 0)
                {
                    await SendMessageAsync(message.ChatId, $"Uso: /removerimg <id|ultimo> 1,3,5", ct);
                    return;
                }

                var max = draft.ImageUrls?.Count ?? 0;
                if (max == 0)
                {
                    await SendMessageAsync(message.ChatId, $"Draft {ShortDraftId(draft.Id)} sem imagens para remover.", ct);
                    return;
                }

                var toRemove = parsed.Indexes.Where(i => i >= 1 && i <= max).Distinct().OrderBy(i => i).ToList();
                if (toRemove.Count == 0)
                {
                    await SendMessageAsync(message.ChatId, $"Indice invalido. Use valores entre 1 e {max}.", ct);
                    return;
                }

                var before = (draft.ImageUrls ?? new List<string>()).ToList();
                draft.ImageUrls = before
                    .Where((_, idx) => !toRemove.Contains(idx + 1))
                    .ToList();
                draft.SelectedImageIndexes = draft.ImageUrls.Count > 0 ? new List<int> { 1 } : new List<int>();
                draft.Status = "draft";
                draft.Error = null;
                await _publishStore.UpdateAsync(draft, ct);
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "tg_draft_remove_images",
                    Success = true,
                    DraftId = draft.Id,
                    Details = $"Removed={string.Join(",", toRemove)};Remaining={draft.ImageUrls.Count};Chat={message.ChatId}"
                }, ct);

                await SendMessageAsync(
                    message.ChatId,
                    $"Imagens removidas do draft {ShortDraftId(draft.Id)}: {string.Join(", ", toRemove)}.\nRestantes: {draft.ImageUrls.Count}.",
                    ct);
                return;
            }

            case "titulo":
            case "title":
            {
                var parsed = ParseDraftTextArguments(command.Arguments);
                var (draft, error) = await ResolveDraftAsync(parsed.DraftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }
                if (string.IsNullOrWhiteSpace(parsed.Text))
                {
                    await SendMessageAsync(message.ChatId, "Uso: /titulo <draft|ultimo> <novo titulo>", ct);
                    return;
                }

                draft.ProductName = parsed.Text.Trim();
                draft.Status = "draft";
                draft.Error = null;
                await _publishStore.UpdateAsync(draft, ct);
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "tg_draft_set_title",
                    Success = true,
                    DraftId = draft.Id,
                    Details = $"TitleLength={draft.ProductName.Length};Chat={message.ChatId}"
                }, ct);

                await SendMessageAsync(message.ChatId, $"Titulo atualizado no draft {ShortDraftId(draft.Id)}.", ct);
                return;
            }

            case "legenda":
            case "caption":
            {
                var parsed = ParseDraftTextArguments(command.Arguments);
                var (draft, error) = await ResolveDraftAsync(parsed.DraftRef, ct);
                if (draft is null)
                {
                    await SendMessageAsync(message.ChatId, error ?? "Rascunho nao encontrado.", ct);
                    return;
                }
                if (string.IsNullOrWhiteSpace(parsed.Text))
                {
                    await SendMessageAsync(message.ChatId, "Uso: /legenda <draft|ultimo> <texto da legenda>", ct);
                    return;
                }

                var caption = parsed.Text.Trim();
                if (caption.Length > 2200)
                {
                    caption = caption[..2200].TrimEnd() + "...";
                }

                draft.Caption = caption;
                draft.CaptionOptions = new List<string> { caption };
                draft.SelectedCaptionIndex = 1;
                draft.Status = "draft";
                draft.Error = null;
                await _publishStore.UpdateAsync(draft, ct);
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "tg_draft_set_caption",
                    Success = true,
                    DraftId = draft.Id,
                    Details = $"CaptionLength={caption.Length};Chat={message.ChatId}"
                }, ct);

                await SendMessageAsync(message.ChatId, $"Legenda atualizada no draft {ShortDraftId(draft.Id)}.", ct);
                return;
            }

            case "story":
            case "autostory":
            {
                var options = ParseAutoPilotCommandOptions(command.Arguments);
                await SendMessageAsync(message.ChatId, "Executando autostory...", ct);
                var result = await _instagramAutoPilotService.RunNowAsync(new InstagramAutoPilotRunRequest
                {
                    PostType = "story",
                    TopCount = options.TopCount,
                    SendForApproval = true,
                    ApprovalChannel = "telegram",
                    ApprovalTelegramChatId = message.ChatId,
                    DryRun = options.DryRun,
                    ForceIncludeExisting = options.ForceIncludeExisting
                }, ct);
                await SendMessageAsync(message.ChatId, BuildAutoPilotResultMessage(result), ct);
                return;
            }

            case "post":
            case "autopilot":
            {
                var options = ParseAutoPilotCommandOptions(command.Arguments);
                await SendMessageAsync(message.ChatId, "Executando autopilot de post...", ct);
                var result = await _instagramAutoPilotService.RunNowAsync(new InstagramAutoPilotRunRequest
                {
                    PostType = "feed",
                    TopCount = options.TopCount,
                    SendForApproval = true,
                    ApprovalChannel = "telegram",
                    ApprovalTelegramChatId = message.ChatId,
                    DryRun = options.DryRun,
                    ForceIncludeExisting = options.ForceIncludeExisting
                }, ct);
                await SendMessageAsync(message.ChatId, BuildAutoPilotResultMessage(result), ct);
                return;
            }

            default:
                await SendMessageAsync(message.ChatId, "Comando nao reconhecido. Use /help para ver os comandos de revisao e autopilot.", ct);
                return;
        }
    }

    private bool IsBotCommandAuthorized(long chatId, AutomationSettings settings)
    {
        var allowed = new HashSet<long>();

        if (_options.DestinationChatId != 0) allowed.Add(_options.DestinationChatId);
        if (_options.LogsChatId != 0) allowed.Add(_options.LogsChatId);

        var forwarding = settings.TelegramForwarding?.DestinationChatId ?? 0;
        if (forwarding != 0) allowed.Add(forwarding);

        var instaPost = settings.InstagramPosts;
        foreach (var id in instaPost?.TelegramChatIds ?? [])
        {
            if (id != 0) allowed.Add(id);
        }

        var responder = settings.LinkResponder;
        foreach (var id in responder?.TelegramChatIds ?? [])
        {
            if (id != 0) allowed.Add(id);
        }

        var instaPublish = settings.InstagramPublish;
        if ((instaPublish?.AutoPilotApprovalTelegramChatId ?? 0) != 0)
        {
            allowed.Add(instaPublish!.AutoPilotApprovalTelegramChatId);
        }
        if ((instaPublish?.StoryAutoPilotApprovalTelegramChatId ?? 0) != 0)
        {
            allowed.Add(instaPublish!.StoryAutoPilotApprovalTelegramChatId);
        }

        return allowed.Count > 0 && allowed.Contains(chatId);
    }

    private string BuildStatusMessage(AutomationSettings settings)
    {
        var uptime = DateTimeOffset.UtcNow - _startedAt;
        var instaPublish = settings.InstagramPublish ?? new InstagramPublishSettings();
        var responder = settings.LinkResponder ?? new LinkResponderSettings();
        var lines = new List<string>
        {
            "STATUS BOT",
            $"Uptime: {uptime:dd\\.hh\\:mm\\:ss}",
            $"Bot: {(!string.IsNullOrWhiteSpace(_options.BotToken) ? "configurado" : "nao configurado")}",
            $"Link responder telegram: {(responder.Enabled && responder.AllowTelegramBot ? "ON" : "OFF")}",
            $"Autopilot feed: {(instaPublish.AutoPilotEnabled ? "ON" : "OFF")} (intervalo {instaPublish.AutoPilotIntervalMinutes}m)",
            $"Autostory: {(instaPublish.StoryAutoPilotEnabled ? "ON" : "OFF")} (intervalo {instaPublish.StoryAutoPilotIntervalMinutes}m)",
            $"Aprovacao feed: {instaPublish.AutoPilotApprovalChannel} ({instaPublish.AutoPilotApprovalTelegramChatId})",
            $"Aprovacao story: {instaPublish.StoryAutoPilotApprovalChannel} ({instaPublish.StoryAutoPilotApprovalTelegramChatId})"
        };

        return string.Join('\n', lines);
    }

    private static string BuildHelpMessage(long chatId)
    {
        var lines = new List<string>
        {
            "COMANDOS DISPONIVEIS",
            "/help - mostra este menu",
            "/status - status do bot e autopilots",
            "/chatid - mostra o id do chat atual",
            "/assist <mensagem> - conversa com IA",
            "/codex <mensagem> - alias de /assist",
            "/assistclear - limpa contexto da IA neste chat",
            "/lista [n] - lista drafts mais recentes",
            "/revisar [id|ultimo] - revisa draft",
            "/trocarimg [id|ultimo] - busca novas imagens do link do produto",
            "/img [id|ultimo] [1|1,2|2-4] - seleciona imagem(ns)",
            "/removerimg [id|ultimo] 1,3,5 - remove imagem(ns) do draft",
            "/titulo [id|ultimo] <texto> - ajusta nome do produto",
            "/legenda [id|ultimo] <texto> - ajusta copy",
            "/aprovar [id|ultimo] - marca draft como aprovado",
            "/reprovar [id|ultimo] <motivo> - marca draft como reprovado",
            "/story [top] [dry] [force] - roda autostory (ex.: /story 2)",
            "/post [top] [dry] [force] - roda autopilot feed (ex.: /post 3)",
            "/ping - teste rapido",
            "",
            "Conversacional:",
            " - \"bot a imagem nao bate, troca a imagem do draft 2\"",
            " - \"bot remover imagem 1,3 e 5 do draft 2\"",
            " - \"bot revisa o draft 1\"",
            " - \"bot aprova o draft 1\"",
            " - \"bot roda autostory top 2 dry\"",
            " - \"bot essa imagem nao combina com o produto, o que voce sugere?\"",
            $"Chat atual: {chatId}"
        };

        return string.Join('\n', lines);
    }

    private static string BuildAutoPilotResultMessage(InstagramAutoPilotRunResult result)
    {
        var lines = new List<string>
        {
            $"Resultado {result.PostType}",
            $"Sucesso: {(result.Success ? "sim" : "nao")}",
            $"Selecionados: {result.SelectedCount}",
            $"Drafts: {result.DraftsCreated}",
            $"Aprovacao enviada: {(result.ApprovalSent ? "sim" : "nao")}",
            $"Canal aprovacao: {result.ApprovalChannel ?? "-"}",
            $"Destino aprovacao: {result.ApprovalTarget ?? "-"}"
        };

        if (result.Selected.Count > 0)
        {
            lines.Add("Top selecionados:");
            var top = result.Selected.Take(3).ToList();
            for (var i = 0; i < top.Count; i++)
            {
                var item = top[i];
                var title = string.IsNullOrWhiteSpace(item.ProductName) ? "(sem nome)" : item.ProductName;
                lines.Add($"{i + 1}. {title}");
            }
        }

        if (!string.IsNullOrWhiteSpace(result.Message))
        {
            lines.Add(result.Message);
        }

        return string.Join('\n', lines);
    }

    private async Task<string> BuildDraftListMessageAsync(int limit, CancellationToken ct)
    {
        var items = await _publishStore.ListAsync(ct);
        var ordered = items
            .OrderByDescending(x => x.CreatedAt)
            .Take(Math.Clamp(limit, 1, 20))
            .ToList();

        if (ordered.Count == 0)
        {
            return "Nenhum rascunho encontrado.";
        }

        var lines = new List<string> { $"RASCUNHOS RECENTES ({ordered.Count})" };
        for (var i = 0; i < ordered.Count; i++)
        {
            var draft = ordered[i];
            var product = string.IsNullOrWhiteSpace(draft.ProductName) ? "(sem produto)" : draft.ProductName.Trim();
            if (product.Length > 70)
            {
                product = product[..70].TrimEnd() + "...";
            }

            lines.Add($"{i + 1}. {ShortDraftId(draft.Id)} | {draft.Status} | {NormalizePostType(draft.PostType)} | {product}");
        }

        lines.Add("Comandos: /revisar 1 | /aprovar 1 | /reprovar 1 motivo | /trocarimg 1");
        return string.Join('\n', lines);
    }

    private async Task<(InstagramPublishDraft? Draft, string? Error)> ResolveDraftAsync(string? idOrAlias, CancellationToken ct)
    {
        var items = await _publishStore.ListAsync(ct);
        if (items.Count == 0)
        {
            return (null, "Nenhum rascunho encontrado.");
        }

        var key = (idOrAlias ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(key) || string.Equals(key, "ultimo", StringComparison.OrdinalIgnoreCase))
        {
            return (items.OrderByDescending(x => x.CreatedAt).First(), null);
        }

        if (int.TryParse(key, out var indexRef) && indexRef > 0)
        {
            var ordered = items
                .OrderByDescending(x => x.CreatedAt)
                .ToList();
            if (indexRef <= ordered.Count)
            {
                return (ordered[indexRef - 1], null);
            }

            return (null, $"Indice {indexRef} fora do intervalo. Existem {ordered.Count} rascunhos.");
        }

        var exact = items.FirstOrDefault(x => string.Equals(x.Id, key, StringComparison.OrdinalIgnoreCase));
        if (exact is not null)
        {
            return (exact, null);
        }

        var partials = items
            .Where(x => x.Id.StartsWith(key, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.CreatedAt)
            .ToList();
        if (partials.Count == 1)
        {
            return (partials[0], null);
        }
        if (partials.Count > 1)
        {
            return (null, "ID parcial ambiguo. Envie mais caracteres do draft.");
        }

        return (null, $"Rascunho '{key}' nao encontrado.");
    }

    private static string BuildDraftReviewMessage(InstagramPublishDraft draft)
    {
        var sb = new StringBuilder();
        var shortId = ShortDraftId(draft.Id);

        sb.AppendLine($"Draft: {draft.Id}");
        sb.AppendLine($"Alias curto: {shortId}");
        sb.AppendLine($"Status: {draft.Status}");
        sb.AppendLine($"Tipo: {NormalizePostType(draft.PostType)}");
        sb.AppendLine($"Criado em: {draft.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC");
        if (!string.IsNullOrWhiteSpace(draft.ProductName))
        {
            sb.AppendLine($"Produto: {draft.ProductName}");
        }

        var imageCount = draft.ImageUrls?.Count ?? 0;
        sb.AppendLine($"Imagens: {imageCount}");
        var selectedIndexes = SanitizeSelectedIndexes(draft.SelectedImageIndexes, imageCount);
        if (selectedIndexes.Count > 0)
        {
            sb.AppendLine($"Selecionadas: {string.Join(", ", selectedIndexes)}");
        }
        else if (imageCount > 0)
        {
            sb.AppendLine("Selecionadas: todas");
        }

        if (!string.IsNullOrWhiteSpace(draft.Error))
        {
            sb.AppendLine($"Observacao: {draft.Error}");
        }

        var caption = draft.Caption ?? string.Empty;
        if (caption.Length > 500)
        {
            caption = caption[..500].TrimEnd() + "...";
        }

        sb.AppendLine();
        sb.AppendLine("Legenda atual:");
        sb.AppendLine(string.IsNullOrWhiteSpace(caption) ? "(vazia)" : caption);

        if (imageCount > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Imagens (top 5):");
            var list = (draft.ImageUrls ?? new List<string>()).Take(5).ToList();
            for (var i = 0; i < list.Count; i++)
            {
                sb.AppendLine($"{i + 1}) {list[i]}");
            }
        }

        sb.AppendLine();
        sb.AppendLine($"Acoes: /img {shortId} 1 | /removerimg {shortId} 1,3 | /trocarimg {shortId} | /titulo {shortId} ... | /legenda {shortId} ... | /aprovar {shortId} | /reprovar {shortId} motivo");
        return sb.ToString().Trim();
    }

    private static string BuildDraftImageListMessage(InstagramPublishDraft draft)
    {
        var shortId = ShortDraftId(draft.Id);
        if (draft.ImageUrls.Count == 0)
        {
            return $"Draft {shortId} sem imagens. Use /trocarimg {shortId}.";
        }

        var selectedIndexes = SanitizeSelectedIndexes(draft.SelectedImageIndexes, draft.ImageUrls.Count);
        var sb = new StringBuilder();
        sb.AppendLine($"Imagens do draft {shortId}:");
        for (var i = 0; i < draft.ImageUrls.Count; i++)
        {
            sb.AppendLine($"{i + 1}) {draft.ImageUrls[i]}");
        }

        sb.AppendLine();
        sb.AppendLine($"Selecionadas: {(selectedIndexes.Count > 0 ? string.Join(", ", selectedIndexes) : "todas")}");
        sb.AppendLine($"Escolher: /img {shortId} 1 ou /img {shortId} 1,2");
        return sb.ToString().Trim();
    }

    private async Task<string> ReplaceDraftImageAsync(InstagramPublishDraft draft, long chatId, CancellationToken ct)
    {
        var sourceLink = draft.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link))?.Link
                         ?? ExtractFirstUrl(draft.Caption)
                         ?? ExtractFirstUrl(string.Join(" ", draft.CaptionOptions ?? new List<string>()));
        if (string.IsNullOrWhiteSpace(sourceLink))
        {
            return $"Draft {ShortDraftId(draft.Id)} sem link de origem para buscar novas imagens.";
        }

        var meta = await _instagramMeta.GetMetaAsync(sourceLink, ct);
        var discovered = NormalizeExternalUrls(meta.Images, 18)
            .OrderByDescending(url => ScoreImageCandidate(url, draft.ProductName))
            .ToList();

        if (discovered.Count == 0)
        {
            return "Nao encontrei novas imagens no link de origem.";
        }

        var merged = NormalizeExternalUrls(discovered.Concat(draft.ImageUrls ?? new List<string>()), 20);
        draft.ImageUrls = merged;
        draft.SelectedImageIndexes = merged.Count > 0 ? new List<int> { 1 } : new List<int>();
        draft.Status = "draft";
        draft.Error = null;

        await _publishStore.UpdateAsync(draft, ct);
        await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "tg_draft_replace_image",
            Success = true,
            DraftId = draft.Id,
            Details = $"Source={sourceLink};Images={merged.Count};Chat={chatId}"
        }, ct);

        var preview = merged.FirstOrDefault();
        var score = preview is null ? 0 : ScoreImageCandidate(preview, draft.ProductName);
        return string.Join('\n', new[]
        {
            $"Imagem principal atualizada no draft {ShortDraftId(draft.Id)}.",
            $"Total de imagens: {merged.Count}",
            $"Score estimado da imagem principal: {score}/100",
            preview is null ? "Sem preview de URL." : $"Preview: {preview}",
            $"Se quiser outra imagem: /img {ShortDraftId(draft.Id)} 2"
        });
    }

    private static int ScoreImageCandidate(string imageUrl, string? productName)
    {
        if (string.IsNullOrWhiteSpace(imageUrl))
        {
            return 0;
        }

        var score = 45;
        if (imageUrl.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase)
            || imageUrl.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase)
            || imageUrl.EndsWith(".png", StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
        }
        if (imageUrl.EndsWith(".webp", StringComparison.OrdinalIgnoreCase))
        {
            score -= 10;
        }

        if (imageUrl.Contains("logo", StringComparison.OrdinalIgnoreCase)
            || imageUrl.Contains("icon", StringComparison.OrdinalIgnoreCase)
            || imageUrl.Contains("avatar", StringComparison.OrdinalIgnoreCase))
        {
            score -= 25;
        }

        var tokens = ExtractMeaningfulTokens(productName, 3);
        var loweredUrl = imageUrl.ToLowerInvariant();
        var matched = tokens.Count(token => loweredUrl.Contains(token, StringComparison.OrdinalIgnoreCase));
        score += Math.Min(matched * 6, 30);

        return Math.Clamp(score, 1, 100);
    }

    private static HashSet<string> ExtractMeaningfulTokens(string? text, int minLength)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        return Regex.Matches(text.ToLowerInvariant(), @"[a-z0-9]+", RegexOptions.CultureInvariant)
            .Select(match => match.Value.Trim())
            .Where(token => token.Length >= minLength)
            .Where(token => !CommonStopWords.Contains(token))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static string? ExtractFirstUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = UrlRegex.Match(text);
        return match.Success ? match.Value : null;
    }

    private static List<string> NormalizeExternalUrls(IEnumerable<string>? urls, int maxItems)
    {
        if (urls is null)
        {
            return new List<string>();
        }

        return urls
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Where(IsLikelyImageUrl)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, maxItems))
            .ToList();
    }

    private static bool IsLikelyImageUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var abs = value.ToLowerInvariant();
        if (abs.Contains(".mp4") || abs.Contains(".webm") || abs.Contains(".mov"))
        {
            return false;
        }

        return abs.Contains(".jpg")
               || abs.Contains(".jpeg")
               || abs.Contains(".png")
               || abs.Contains(".webp")
               || abs.Contains("image")
               || abs.Contains("img");
    }

    private static List<int> SanitizeSelectedIndexes(IEnumerable<int>? indexes, int maxCount)
    {
        if (indexes is null || maxCount <= 0)
        {
            return new List<int>();
        }

        return indexes
            .Where(i => i >= 1 && i <= maxCount)
            .Distinct()
            .OrderBy(i => i)
            .ToList();
    }

    private static string NormalizePostType(string? postType)
    {
        var value = (postType ?? "feed").Trim().ToLowerInvariant();
        return value is "feed" or "story" ? value : "feed";
    }

    private static string ShortDraftId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return "desconhecido";
        }

        return id.Length > 8 ? id[..8] : id;
    }

    private static DraftTextArguments ParseDraftTextArguments(string[] arguments)
    {
        if (arguments.Length == 0)
        {
            return new DraftTextArguments("ultimo", string.Empty);
        }

        if (arguments.Length == 1)
        {
            if (LooksLikeDraftReference(arguments[0]))
            {
                return new DraftTextArguments(arguments[0], string.Empty);
            }

            return new DraftTextArguments("ultimo", arguments[0]);
        }

        if (LooksLikeDraftReference(arguments[0]))
        {
            return new DraftTextArguments(arguments[0], string.Join(' ', arguments.Skip(1)).Trim());
        }

        return new DraftTextArguments("ultimo", string.Join(' ', arguments).Trim());
    }

    private static ImageCommandArguments ParseImageCommandArguments(string[] arguments)
    {
        if (arguments.Length == 0)
        {
            return new ImageCommandArguments("ultimo", new List<int>());
        }

        if (arguments.Length == 1)
        {
            if (TryParseImageIndexes(arguments[0], out var indexes))
            {
                return new ImageCommandArguments("ultimo", indexes);
            }

            return new ImageCommandArguments(arguments[0], new List<int>());
        }

        var draftRef = arguments[0];
        var indexRaw = string.Join(' ', arguments.Skip(1)).Trim();
        if (!TryParseImageIndexes(indexRaw, out var parsed))
        {
            parsed = new List<int>();
        }

        return new ImageCommandArguments(draftRef, parsed);
    }

    private static bool TryParseImageIndexes(string input, out List<int> indexes)
    {
        indexes = new List<int>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var normalized = input.ToLowerInvariant().Trim();
        normalized = normalized
            .Replace(" e ", ",", StringComparison.Ordinal)
            .Replace(";", ",", StringComparison.Ordinal)
            .Replace("|", ",", StringComparison.Ordinal);
        normalized = Regex.Replace(normalized, @"[^\d,\-\s]", " ", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"(?<=\d)\s+(?=\d)", ",", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"\s+", " ", RegexOptions.CultureInvariant).Trim();

        var parts = normalized.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            if (part.Contains('-', StringComparison.Ordinal))
            {
                var range = part.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (range.Length == 2
                    && int.TryParse(range[0], out var start)
                    && int.TryParse(range[1], out var end))
                {
                    if (end < start)
                    {
                        (start, end) = (end, start);
                    }

                    for (var i = start; i <= end; i++)
                    {
                        indexes.Add(i);
                    }
                    continue;
                }
            }

            if (int.TryParse(part, out var single))
            {
                indexes.Add(single);
            }
        }

        indexes = indexes.Distinct().OrderBy(x => x).ToList();
        return indexes.Count > 0;
    }

    private static bool LooksLikeDraftReference(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var token = value.Trim().ToLowerInvariant();
        if (token == "ultimo")
        {
            return true;
        }

        if (int.TryParse(token, out var index) && index > 0)
        {
            return true;
        }

        return Regex.IsMatch(token, "^[a-z0-9]{4,32}$", RegexOptions.CultureInvariant);
    }

    private static bool TryParseConversationalCommand(string text, out TelegramBotCommand command)
    {
        command = new TelegramBotCommand(string.Empty, []);
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var raw = text.Trim();
        if (raw.StartsWith('/'))
        {
            return false;
        }

        if (!TryNormalizeConversationalInput(raw, out var normalizedRaw))
        {
            return false;
        }

        var lower = normalizedRaw.ToLowerInvariant();
        var draftRef = TryExtractDraftReference(normalizedRaw) ?? "ultimo";

        if (lower.Contains("imagem nao bate", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("imagem não bate", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("troca imagem", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("trocar imagem", StringComparison.OrdinalIgnoreCase))
        {
            command = new TelegramBotCommand("trocarimg", [draftRef]);
            return true;
        }

        if (lower.Contains("reprova", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("rejeita", StringComparison.OrdinalIgnoreCase))
        {
            var reason = ExtractReasonText(normalizedRaw);
            command = string.IsNullOrWhiteSpace(reason)
                ? new TelegramBotCommand("reprovar", [draftRef])
                : new TelegramBotCommand("reprovar", [draftRef, reason]);
            return true;
        }

        if (lower.Contains("aprova", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("confirma", StringComparison.OrdinalIgnoreCase))
        {
            command = new TelegramBotCommand("aprovar", [draftRef]);
            return true;
        }

        if (lower.Contains("revisa", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("mostrar draft", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("ver draft", StringComparison.OrdinalIgnoreCase))
        {
            command = new TelegramBotCommand("revisar", [draftRef]);
            return true;
        }

        var removeImageMatch = Regex.Match(
            lower,
            @"(?:remover|remove|tirar|excluir|apagar)\s+(?:a\s+|as\s+)?imagem(?:ens)?\s+(?<idx>[\d,\-\se]+)",
            RegexOptions.CultureInvariant);
        if (removeImageMatch.Success && TryParseImageIndexes(removeImageMatch.Groups["idx"].Value, out var removeIndexes) && removeIndexes.Count > 0)
        {
            command = new TelegramBotCommand("removerimg", [draftRef, string.Join(",", removeIndexes)]);
            return true;
        }

        var useImageMatch = Regex.Match(
            lower,
            @"(?:usar|selecionar|escolher)\s+(?:a\s+|as\s+)?imagem(?:ens)?\s+(?<idx>[\d,\-\se]+)",
            RegexOptions.CultureInvariant);
        if (useImageMatch.Success && TryParseImageIndexes(useImageMatch.Groups["idx"].Value, out var selectedIndexes) && selectedIndexes.Count > 0)
        {
            command = new TelegramBotCommand("img", [draftRef, string.Join(",", selectedIndexes)]);
            return true;
        }

        if (lower.StartsWith("titulo ", StringComparison.OrdinalIgnoreCase) || lower.StartsWith("título ", StringComparison.OrdinalIgnoreCase))
        {
            var textPart = ExtractTextAfterKeyword(normalizedRaw, "titulo");
            if (!string.IsNullOrWhiteSpace(textPart))
            {
                command = new TelegramBotCommand("titulo", [draftRef, textPart]);
                return true;
            }
        }

        if (lower.StartsWith("legenda ", StringComparison.OrdinalIgnoreCase))
        {
            var textPart = ExtractTextAfterKeyword(normalizedRaw, "legenda");
            if (!string.IsNullOrWhiteSpace(textPart))
            {
                command = new TelegramBotCommand("legenda", [draftRef, textPart]);
                return true;
            }
        }

        return false;
    }

    private static bool TryNormalizeConversationalInput(string raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var trimmed = raw.Trim();
        var lower = trimmed.ToLowerInvariant();

        // Evita misturar com conversa geral do grupo: modo conversacional
        // so ativa com palavra de chamada explicita.
        var wakePrefixes = new[]
        {
            "bot ",
            "postagemstory ",
            "assistente ",
            "rei "
        };

        foreach (var prefix in wakePrefixes)
        {
            if (lower.StartsWith(prefix, StringComparison.Ordinal))
            {
                normalized = trimmed[prefix.Length..].Trim();
                return !string.IsNullOrWhiteSpace(normalized);
            }
        }

        var mention = "@postagemstory_bot";
        var mentionIndex = lower.IndexOf(mention, StringComparison.Ordinal);
        if (mentionIndex >= 0)
        {
            normalized = trimmed.Replace("@PostagemStory_bot", string.Empty, StringComparison.OrdinalIgnoreCase).Trim();
            return !string.IsNullOrWhiteSpace(normalized);
        }

        return false;
    }

    private static string? TryExtractDraftReference(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var lowered = text.ToLowerInvariant();
        if (lowered.Contains("ultimo", StringComparison.OrdinalIgnoreCase))
        {
            return "ultimo";
        }

        var match = Regex.Match(
            lowered,
            @"(?:draft|rascunho|post)\s*(?<id>[a-z0-9]{4,32}|\d+)",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        if (match.Success)
        {
            return match.Groups["id"].Value;
        }

        return null;
    }

    private static string ExtractReasonText(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        var match = Regex.Match(
            text,
            @"(?:motivo|porque|por que|:)\s*(?<reason>.+)$",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        if (match.Success)
        {
            return match.Groups["reason"].Value.Trim();
        }

        return string.Empty;
    }

    private static string ExtractTextAfterKeyword(string text, string keyword)
    {
        if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(keyword))
        {
            return string.Empty;
        }

        var idx = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return string.Empty;
        }

        var remaining = text[(idx + keyword.Length)..].Trim();
        remaining = remaining.Trim(':', '-', '=', ' ');
        return remaining;
    }

    private static AutoPilotCommandOptions ParseAutoPilotCommandOptions(string[] arguments)
    {
        int? topCount = null;
        var dryRun = false;
        var forceIncludeExisting = false;

        foreach (var arg in arguments)
        {
            if (string.IsNullOrWhiteSpace(arg))
            {
                continue;
            }

            if (!topCount.HasValue && int.TryParse(arg, out var parsedTop))
            {
                topCount = Math.Clamp(parsedTop, 1, 10);
                continue;
            }

            if (string.Equals(arg, "dry", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "--dry", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "teste", StringComparison.OrdinalIgnoreCase))
            {
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "force", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "--force", StringComparison.OrdinalIgnoreCase))
            {
                forceIncludeExisting = true;
            }
        }

        return new AutoPilotCommandOptions(topCount, dryRun, forceIncludeExisting);
    }

    private static bool TryParseBotCommand(string text, string? botUsername, out TelegramBotCommand command)
    {
        command = new TelegramBotCommand(string.Empty, []);
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        if (!trimmed.StartsWith('/'))
        {
            return false;
        }

        var pieces = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (pieces.Length == 0)
        {
            return false;
        }

        var rawHead = pieces[0];
        var commandToken = rawHead;
        var mentionIdx = rawHead.IndexOf('@');
        if (mentionIdx > 0)
        {
            var mention = rawHead[(mentionIdx + 1)..];
            if (!string.IsNullOrWhiteSpace(botUsername)
                && !string.Equals(mention, botUsername, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            commandToken = rawHead[..mentionIdx];
        }

        var name = commandToken.TrimStart('/').Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        var args = pieces.Skip(1).ToArray();
        command = new TelegramBotCommand(name, args);
        return true;
    }

    private async Task<TelegramBotCommand?> TryResolveAssistantCommandAsync(string userInput, AutomationSettings settings, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userInput))
        {
            return null;
        }

        var providerRaw = settings.InstagramPosts?.AiProvider ?? "openai";
        var provider = providerRaw.Trim().ToLowerInvariant();
        var providers = provider switch
        {
            "gemini" => new[] { "gemini", "openai" },
            "both" => new[] { "openai", "gemini" },
            _ => new[] { "openai", "gemini" }
        };

        foreach (var item in providers)
        {
            string? raw = null;
            if (string.Equals(item, "openai", StringComparison.Ordinal))
            {
                raw = await TryResolveAssistantCommandOpenAiAsync(userInput, settings.OpenAI, ct);
            }
            else if (string.Equals(item, "gemini", StringComparison.Ordinal))
            {
                raw = await TryResolveAssistantCommandGeminiAsync(userInput, settings.Gemini, ct);
            }

            if (TryParseAssistantCommand(raw, out var command))
            {
                return command;
            }
        }

        return null;
    }

    private async Task<string?> TryResolveAssistantCommandOpenAiAsync(string userInput, OpenAISettings settings, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(settings.ApiKey) || settings.ApiKey == "********")
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(settings.Model) ? "gpt-4o-mini" : settings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(settings.BaseUrl) ? "https://api.openai.com/v1" : settings.BaseUrl.Trim();
        var prompt = BuildAssistantCommandPrompt(userInput);
        var payload = new
        {
            model,
            input = new object[]
            {
                new
                {
                    role = "system",
                    content = "Converta pedidos em JSON para comando de bot. Responda somente JSON valido."
                },
                new
                {
                    role = "user",
                    content = prompt
                }
            },
            temperature = 0.1,
            max_output_tokens = 260
        };

        try
        {
            var client = _httpClientFactory.CreateClient("openai");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", settings.ApiKey);
            using var response = await client.PostAsync(
                $"{baseUrl.TrimEnd('/')}/responses",
                new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
                ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            return ExtractOpenAiOutputText(body);
        }
        catch
        {
            return null;
        }
    }

    private async Task<string?> TryResolveAssistantCommandGeminiAsync(string userInput, GeminiSettings settings, CancellationToken ct)
    {
        var keys = GetGeminiApiKeys(settings);
        if (keys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(settings.Model) ? "gemini-2.5-flash" : settings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(settings.BaseUrl) ? "https://generativelanguage.googleapis.com/v1beta" : settings.BaseUrl.Trim();
        var prompt = BuildAssistantCommandPrompt(userInput);
        var payload = new
        {
            contents = new[]
            {
                new
                {
                    role = "user",
                    parts = new[] { new { text = prompt } }
                }
            },
            generationConfig = new
            {
                maxOutputTokens = 320
            }
        };

        try
        {
            var client = _httpClientFactory.CreateClient("gemini");
            for (var i = 0; i < keys.Count; i++)
            {
                var url = $"{baseUrl.TrimEnd('/')}/models/{model}:generateContent?key={Uri.EscapeDataString(keys[i])}";
                using var response = await client.PostAsync(url, new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"), ct);
                var body = await response.Content.ReadAsStringAsync(ct);
                if (!response.IsSuccessStatusCode)
                {
                    var canTryNext = i < keys.Count - 1 && ShouldTryNextGeminiKey(response.StatusCode, body);
                    if (canTryNext)
                    {
                        continue;
                    }
                    return null;
                }

                return ExtractGeminiOutputText(body);
            }
        }
        catch
        {
        }

        return null;
    }

    private static string BuildAssistantCommandPrompt(string userInput)
    {
        return
            "Tarefa: analisar mensagem e devolver somente JSON com intencao de comando.\n" +
            "Acoes validas: none, help, status, chatid, ping, lista, revisar, aprovar, reprovar, trocarimg, img, removerimg, titulo, legenda, story, post, assistclear.\n" +
            "Campos JSON:\n" +
            "{\n" +
            "  \"action\": \"none|...\",\n" +
            "  \"draftRef\": \"ultimo|numero|id_curto\",\n" +
            "  \"indexes\": [1,2],\n" +
            "  \"text\": \"motivo/titulo/legenda\",\n" +
            "  \"topCount\": 1,\n" +
            "  \"dryRun\": false,\n" +
            "  \"force\": false\n" +
            "}\n" +
            "Regras:\n" +
            "- Se nao for pedido de acao, use action=none.\n" +
            "- Para story/post, interpretar 'dry' ou 'teste' em dryRun=true.\n" +
            "- Para img/removerimg, preencher indexes.\n" +
            "- Se faltar draftRef, usar 'ultimo'.\n" +
            "- Responda somente JSON, sem markdown.\n\n" +
            $"Mensagem: {userInput}";
    }

    private static bool TryParseAssistantCommand(string? raw, out TelegramBotCommand? command)
    {
        command = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var json = ExtractJsonObject(raw);
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var action = GetString(root, "action")?.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(action) || action == "none")
            {
                return false;
            }

            var draftRef = GetString(root, "draftRef");
            if (string.IsNullOrWhiteSpace(draftRef))
            {
                draftRef = "ultimo";
            }
            var text = GetString(root, "text")?.Trim() ?? string.Empty;
            var indexes = new List<int>();
            if (root.TryGetProperty("indexes", out var idxNode) && idxNode.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in idxNode.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out var parsed) && parsed > 0)
                    {
                        indexes.Add(parsed);
                    }
                }
            }

            int? topCount = null;
            if (root.TryGetProperty("topCount", out var topNode) && topNode.ValueKind == JsonValueKind.Number && topNode.TryGetInt32(out var top))
            {
                topCount = Math.Clamp(top, 1, 10);
            }

            var dryRun = root.TryGetProperty("dryRun", out var dryNode) && dryNode.ValueKind == JsonValueKind.True;
            var force = root.TryGetProperty("force", out var forceNode) && forceNode.ValueKind == JsonValueKind.True;

            command = action switch
            {
                "help" => new TelegramBotCommand("help", []),
                "status" => new TelegramBotCommand("status", []),
                "chatid" => new TelegramBotCommand("chatid", []),
                "ping" => new TelegramBotCommand("ping", []),
                "lista" => topCount.HasValue
                    ? new TelegramBotCommand("lista", [topCount.Value.ToString()])
                    : new TelegramBotCommand("lista", []),
                "revisar" => new TelegramBotCommand("revisar", [draftRef]),
                "aprovar" => new TelegramBotCommand("aprovar", [draftRef]),
                "reprovar" => string.IsNullOrWhiteSpace(text)
                    ? new TelegramBotCommand("reprovar", [draftRef])
                    : new TelegramBotCommand("reprovar", [draftRef, text]),
                "trocarimg" => new TelegramBotCommand("trocarimg", [draftRef]),
                "img" when indexes.Count > 0 => new TelegramBotCommand("img", [draftRef, string.Join(",", indexes.Distinct().OrderBy(x => x))]),
                "removerimg" when indexes.Count > 0 => new TelegramBotCommand("removerimg", [draftRef, string.Join(",", indexes.Distinct().OrderBy(x => x))]),
                "titulo" when !string.IsNullOrWhiteSpace(text) => new TelegramBotCommand("titulo", [draftRef, text]),
                "legenda" when !string.IsNullOrWhiteSpace(text) => new TelegramBotCommand("legenda", [draftRef, text]),
                "story" => BuildAutoPilotCommand("story", topCount, dryRun, force),
                "post" => BuildAutoPilotCommand("post", topCount, dryRun, force),
                "assistclear" => new TelegramBotCommand("assistclear", []),
                _ => null
            };

            return command is not null;
        }
        catch
        {
            return false;
        }
    }

    private static TelegramBotCommand BuildAutoPilotCommand(string name, int? topCount, bool dryRun, bool force)
    {
        var args = new List<string>();
        if (topCount.HasValue)
        {
            args.Add(topCount.Value.ToString());
        }
        if (dryRun)
        {
            args.Add("dry");
        }
        if (force)
        {
            args.Add("force");
        }

        return new TelegramBotCommand(name, args.ToArray());
    }

    private static string? ExtractJsonObject(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var start = text.IndexOf('{');
        var end = text.LastIndexOf('}');
        if (start < 0 || end <= start)
        {
            return null;
        }

        return text[start..(end + 1)];
    }

    private async Task<string?> TryGenerateAssistantReplyAsync(long chatId, string userInput, AutomationSettings settings, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userInput))
        {
            return null;
        }

        var providerRaw = settings.InstagramPosts?.AiProvider ?? "openai";
        var provider = providerRaw.Trim().ToLowerInvariant();
        var providers = provider switch
        {
            "gemini" => new[] { "gemini", "openai" },
            "both" => new[] { "openai", "gemini" },
            _ => new[] { "openai", "gemini" }
        };

        var history = GetAssistantHistorySnapshot(chatId);
        string? reply = null;

        foreach (var item in providers)
        {
            if (string.Equals(item, "openai", StringComparison.Ordinal))
            {
                reply = await TryGenerateAssistantReplyOpenAiAsync(history, userInput, settings.OpenAI, ct);
            }
            else if (string.Equals(item, "gemini", StringComparison.Ordinal))
            {
                reply = await TryGenerateAssistantReplyGeminiAsync(history, userInput, settings.Gemini, ct);
            }

            if (!string.IsNullOrWhiteSpace(reply))
            {
                break;
            }
        }

        if (string.IsNullOrWhiteSpace(reply))
        {
            return null;
        }

        AppendAssistantHistory(chatId, "user", userInput);
        AppendAssistantHistory(chatId, "assistant", reply);
        return reply;
    }

    private async Task<string?> TryGenerateAssistantReplyOpenAiAsync(
        IReadOnlyList<AssistantMessage> history,
        string userInput,
        OpenAISettings settings,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(settings.ApiKey) || settings.ApiKey == "********")
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(settings.Model) ? "gpt-4o-mini" : settings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(settings.BaseUrl) ? "https://api.openai.com/v1" : settings.BaseUrl.Trim();

        var input = new List<object>
        {
            new
            {
                role = "system",
                content = BuildAssistantSystemPrompt()
            }
        };

        foreach (var msg in history.TakeLast(AssistantHistoryMaxMessages))
        {
            if (string.IsNullOrWhiteSpace(msg.Content))
            {
                continue;
            }

            var role = string.Equals(msg.Role, "assistant", StringComparison.OrdinalIgnoreCase) ? "assistant" : "user";
            input.Add(new { role, content = msg.Content });
        }

        input.Add(new { role = "user", content = userInput });

        var payload = new
        {
            model,
            input,
            temperature = Math.Clamp(settings.Temperature, 0, 1),
            max_output_tokens = Math.Clamp(settings.MaxOutputTokens <= 0 ? 500 : settings.MaxOutputTokens, 200, 1200)
        };

        try
        {
            var client = _httpClientFactory.CreateClient("openai");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", settings.ApiKey);
            using var response = await client.PostAsync(
                $"{baseUrl.TrimEnd('/')}/responses",
                new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
                ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Assistant OpenAI erro {Status}: {Body}", response.StatusCode, body);
                return null;
            }

            return ExtractOpenAiOutputText(body);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Assistant OpenAI falhou");
            return null;
        }
    }

    private async Task<string?> TryGenerateAssistantReplyGeminiAsync(
        IReadOnlyList<AssistantMessage> history,
        string userInput,
        GeminiSettings settings,
        CancellationToken ct)
    {
        var apiKeys = GetGeminiApiKeys(settings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(settings.Model) ? "gemini-2.5-flash" : settings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(settings.BaseUrl) ? "https://generativelanguage.googleapis.com/v1beta" : settings.BaseUrl.Trim();
        var prompt = BuildGeminiAssistantPrompt(history, userInput);

        var payload = new
        {
            contents = new[]
            {
                new
                {
                    role = "user",
                    parts = new[] { new { text = prompt } }
                }
            },
            generationConfig = new
            {
                maxOutputTokens = Math.Clamp(settings.MaxOutputTokens <= 0 ? 700 : settings.MaxOutputTokens, 200, 1200)
            }
        };

        try
        {
            var client = _httpClientFactory.CreateClient("gemini");
            for (var i = 0; i < apiKeys.Count; i++)
            {
                var key = apiKeys[i];
                var url = $"{baseUrl.TrimEnd('/')}/models/{model}:generateContent?key={Uri.EscapeDataString(key)}";
                using var response = await client.PostAsync(url, new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"), ct);
                var body = await response.Content.ReadAsStringAsync(ct);
                if (!response.IsSuccessStatusCode)
                {
                    var canTryNext = i < apiKeys.Count - 1 && ShouldTryNextGeminiKey(response.StatusCode, body);
                    if (canTryNext)
                    {
                        continue;
                    }

                    _logger.LogWarning("Assistant Gemini erro {Status}: {Body}", response.StatusCode, body);
                    return null;
                }

                return ExtractGeminiOutputText(body);
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Assistant Gemini falhou");
            return null;
        }
    }

    private static string BuildAssistantSystemPrompt()
    {
        return
            "Voce e o assistente operacional do Rei das Ofertas.\n" +
            "Responda sempre em portugues do Brasil, objetivo e pratico.\n" +
            "Seu foco: revisar drafts de post/story, qualidade de imagem x produto, CTA, legenda, e operacao do autopilot.\n" +
            "Quando a pessoa pedir acao operacional, responda com passos curtos e comando exato para executar no bot.\n" +
            "Quando nao houver informacao suficiente, faca no maximo 1 pergunta objetiva.";
    }

    private static string BuildGeminiAssistantPrompt(IReadOnlyList<AssistantMessage> history, string userInput)
    {
        var sb = new StringBuilder();
        sb.AppendLine(BuildAssistantSystemPrompt());
        sb.AppendLine();
        foreach (var msg in history.TakeLast(AssistantHistoryMaxMessages))
        {
            var actor = string.Equals(msg.Role, "assistant", StringComparison.OrdinalIgnoreCase) ? "Assistente" : "Usuario";
            sb.AppendLine($"{actor}: {msg.Content}");
        }
        sb.AppendLine($"Usuario: {userInput}");
        sb.AppendLine("Assistente:");
        return sb.ToString();
    }

    private IReadOnlyList<AssistantMessage> GetAssistantHistorySnapshot(long chatId)
    {
        if (!_assistantHistory.TryGetValue(chatId, out var history))
        {
            return Array.Empty<AssistantMessage>();
        }

        lock (history)
        {
            return history.ToList();
        }
    }

    private void AppendAssistantHistory(long chatId, string role, string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return;
        }

        var history = _assistantHistory.GetOrAdd(chatId, _ => new List<AssistantMessage>());
        lock (history)
        {
            history.Add(new AssistantMessage(role, content.Trim()));
            var overflow = history.Count - AssistantHistoryMaxMessages;
            if (overflow > 0)
            {
                history.RemoveRange(0, overflow);
            }
        }
    }

    private static List<string> GetGeminiApiKeys(GeminiSettings settings)
    {
        var keys = new List<string>();
        if (!string.IsNullOrWhiteSpace(settings.ApiKey) && settings.ApiKey != "********")
        {
            keys.Add(settings.ApiKey.Trim());
        }

        if (settings.ApiKeys is not null)
        {
            foreach (var key in settings.ApiKeys)
            {
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }

                var trimmed = key.Trim();
                if (trimmed == "********")
                {
                    continue;
                }

                keys.Add(trimmed);
            }
        }

        return keys
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private static bool ShouldTryNextGeminiKey(HttpStatusCode statusCode, string? body)
    {
        var status = (int)statusCode;
        if (status is 401 or 403 or 429 or 500 or 502 or 503 or 504)
        {
            return true;
        }

        if (status == 400 && !string.IsNullOrWhiteSpace(body))
        {
            return body.Contains("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase)
                   || body.Contains("quota", StringComparison.OrdinalIgnoreCase)
                   || body.Contains("rate limit", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static string? ExtractOpenAiOutputText(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("output", out var output) || output.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var sb = new StringBuilder();
            foreach (var item in output.EnumerateArray())
            {
                if (!item.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var part in content.EnumerateArray())
                {
                    if (part.TryGetProperty("type", out var typeNode)
                        && string.Equals(typeNode.GetString(), "output_text", StringComparison.OrdinalIgnoreCase)
                        && part.TryGetProperty("text", out var textNode))
                    {
                        var text = textNode.GetString();
                        if (!string.IsNullOrWhiteSpace(text))
                        {
                            sb.AppendLine(text);
                        }
                    }
                }
            }

            var parsed = sb.ToString().Trim();
            return string.IsNullOrWhiteSpace(parsed) ? null : parsed;
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractGeminiOutputText(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("candidates", out var candidates) || candidates.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var candidate in candidates.EnumerateArray())
            {
                if (!candidate.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                if (!content.TryGetProperty("parts", out var parts) || parts.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                var sb = new StringBuilder();
                foreach (var part in parts.EnumerateArray())
                {
                    if (part.TryGetProperty("text", out var textNode))
                    {
                        sb.Append(textNode.GetString());
                    }
                }

                var text = sb.ToString().Trim();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    return text;
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<string> SplitLongMessages(string text, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            yield break;
        }

        var normalized = text.Replace("\r\n", "\n");
        if (normalized.Length <= maxLength)
        {
            yield return normalized;
            yield break;
        }

        var start = 0;
        while (start < normalized.Length)
        {
            var remaining = normalized.Length - start;
            var take = Math.Min(maxLength, remaining);
            var chunk = normalized.Substring(start, take);
            if (take == maxLength)
            {
                var split = chunk.LastIndexOf('\n');
                if (split > maxLength / 3)
                {
                    chunk = chunk[..split];
                    take = split + 1;
                }
            }

            yield return chunk.Trim();
            start += take;
        }
    }

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
    private static readonly HashSet<string> CommonStopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "de", "da", "do", "das", "dos", "para", "com", "sem", "por", "na", "no",
        "e", "ou", "a", "o", "as", "os", "em", "um", "uma", "kit", "produto"
    };

    private sealed record TrackingResult(string Text, List<string> TrackingIds);
    private sealed record TelegramBotCommand(string Name, string[] Arguments);
    private sealed record DraftTextArguments(string DraftRef, string Text);
    private sealed record ImageCommandArguments(string DraftRef, List<int> Indexes);
    private sealed record AutoPilotCommandOptions(int? TopCount, bool DryRun, bool ForceIncludeExisting);
    private sealed record AssistantMessage(string Role, string Content);

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
