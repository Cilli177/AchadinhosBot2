using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramBotApiGateway : ITelegramGateway
{
    private readonly IHttpClientFactory _factory;
    private readonly TelegramOptions _options;
    private readonly ILogger<TelegramBotApiGateway> _logger;

    public TelegramBotApiGateway(IHttpClientFactory factory, IOptions<TelegramOptions> options, ILogger<TelegramBotApiGateway> logger)
    {
        _factory = factory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<TelegramConnectResult> ConnectAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.BotToken))
            return new TelegramConnectResult(false, null, "BotToken não configurado");

        try
        {
            var client = _factory.CreateClient("default");
            var res = await client.GetAsync($"https://api.telegram.org/bot{_options.BotToken}/getMe", cancellationToken);
            var body = await res.Content.ReadAsStringAsync(cancellationToken);

            if (!res.IsSuccessStatusCode)
                return new TelegramConnectResult(false, null, $"Falha getMe: {res.StatusCode}");

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (!root.TryGetProperty("ok", out var okNode) || !okNode.GetBoolean())
                return new TelegramConnectResult(false, null, "Token inválido");

            var username = root.GetProperty("result").GetProperty("username").GetString();
            return new TelegramConnectResult(true, username, "Telegram conectado com sucesso");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao conectar Telegram Bot API");
            return new TelegramConnectResult(false, null, "Erro ao conectar Telegram");
        }
    }
}
