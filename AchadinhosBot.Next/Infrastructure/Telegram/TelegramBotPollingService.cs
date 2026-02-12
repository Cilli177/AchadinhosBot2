using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramBotPollingService : BackgroundService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TelegramOptions _options;
    private readonly IMessageProcessor _messageProcessor;
    private readonly ILogger<TelegramBotPollingService> _logger;
    private long _offset;
    private long? _botUserId;

    public TelegramBotPollingService(
        IHttpClientFactory httpClientFactory,
        IOptions<TelegramOptions> options,
        IMessageProcessor messageProcessor,
        ILogger<TelegramBotPollingService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _messageProcessor = messageProcessor;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_options.BotToken))
        {
            _logger.LogWarning("Telegram BotToken não configurado. Polling não iniciado.");
            return;
        }

        _logger.LogInformation("TelegramBotPollingService iniciado.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_botUserId is null)
                {
                    _botUserId = await TryGetBotUserIdAsync(stoppingToken);
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

    private async Task<long?> TryGetBotUserIdAsync(CancellationToken ct)
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

            var id = root.GetProperty("result").GetProperty("id").GetInt64();
            return id;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro ao obter bot id");
            return null;
        }
    }

    private async Task<List<TelegramUpdate>> GetUpdatesAsync(long offset, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("default");
        var url = $"https://api.telegram.org/bot{_options.BotToken}/getUpdates?timeout=25&offset={offset}";
        var res = await client.GetAsync(url, ct);
        if (!res.IsSuccessStatusCode)
        {
            _logger.LogWarning("getUpdates falhou: {Status}", res.StatusCode);
            return new List<TelegramUpdate>();
        }

        var body = await res.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        if (!root.TryGetProperty("ok", out var okNode) || !okNode.GetBoolean())
        {
            return new List<TelegramUpdate>();
        }

        var list = new List<TelegramUpdate>();
        if (!root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array)
        {
            return list;
        }

        foreach (var item in result.EnumerateArray())
        {
            if (!item.TryGetProperty("update_id", out var updateIdNode))
            {
                continue;
            }

            var update = new TelegramUpdate { UpdateId = updateIdNode.GetInt64() };
            if (TryExtractMessage(item, out var message))
            {
                update.Message = message;
            }

            list.Add(update);
        }

        return list;
    }

    private static bool TryExtractMessage(JsonElement update, out TelegramMessage message)
    {
        message = default!;
        JsonElement msgNode;
        if (update.TryGetProperty("message", out msgNode)
            || update.TryGetProperty("edited_message", out msgNode)
            || update.TryGetProperty("channel_post", out msgNode)
            || update.TryGetProperty("edited_channel_post", out msgNode))
        {
            var text = GetString(msgNode, "text") ?? GetString(msgNode, "caption");
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            var chatId = msgNode.GetProperty("chat").GetProperty("id").GetInt64();
            long? fromId = null;
            if (msgNode.TryGetProperty("from", out var fromNode) && fromNode.TryGetProperty("id", out var fromIdNode))
            {
                fromId = fromIdNode.GetInt64();
            }

            message = new TelegramMessage
            {
                ChatId = chatId,
                FromId = fromId,
                Text = text
            };
            return true;
        }

        return false;
    }

    private async Task HandleUpdateAsync(TelegramUpdate update, CancellationToken ct)
    {
        if (update.Message is null)
        {
            return;
        }

        if (_botUserId.HasValue && update.Message.FromId == _botUserId.Value)
        {
            return;
        }

        var result = await _messageProcessor.ProcessAsync(update.Message.Text, "Telegram", ct);
        if (!result.Success || string.IsNullOrWhiteSpace(result.ConvertedText))
        {
            return;
        }

        await SendMessageAsync(update.Message.ChatId, result.ConvertedText, ct);
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
        }
    }

    private static string? GetString(JsonElement node, string property)
        => node.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

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
    }
}
