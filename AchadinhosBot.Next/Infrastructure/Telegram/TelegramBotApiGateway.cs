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

    public async Task<TelegramConnectResult> ConnectAsync(string? botToken, CancellationToken cancellationToken)
    {
        var tokenToUse = string.IsNullOrWhiteSpace(botToken) ? _options.BotToken : botToken.Trim();
        if (!string.IsNullOrWhiteSpace(tokenToUse) && tokenToUse.StartsWith("bot", StringComparison.OrdinalIgnoreCase))
        {
            tokenToUse = tokenToUse[3..].Trim();
        }
        if (string.IsNullOrWhiteSpace(tokenToUse))
        {
            _logger.LogWarning("Telegram BotToken nÃ£o configurado");
            return new TelegramConnectResult(false, null, "BotToken nÃ£o configurado - verifique variÃ¡vel TELEGRAM_BOT_TOKEN no .env");
        }

        try
        {
            _logger.LogInformation("Validando Telegram Bot Token");
            var client = _factory.CreateClient("default");
            var res = await client.GetAsync($"https://api.telegram.org/bot{tokenToUse}/getMe", cancellationToken);
            var body = await res.Content.ReadAsStringAsync(cancellationToken);

            if (!res.IsSuccessStatusCode)
            {
                var msg = $"Falha getMe: {res.StatusCode} - {body}";
                if (res.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    msg = "Token Telegram invalido. Copie novamente do BotFather no formato 123456:ABC...";
                }
                _logger.LogWarning(msg);
                return new TelegramConnectResult(false, null, msg);
            }

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (!root.TryGetProperty("ok", out var okNode) || !okNode.GetBoolean())
            {
                _logger.LogWarning("Token Telegram invÃ¡lido ou expirado");
                return new TelegramConnectResult(false, null, "Token invÃ¡lido ou expirado");
            }

            var username = root.GetProperty("result").GetProperty("username").GetString();
            _logger.LogInformation("Telegram Bot conectado: @{Username}", username);
            return new TelegramConnectResult(true, username, "Telegram conectado com sucesso");
        }
        catch (HttpRequestException hexc)
        {
            var msg = $"Erro de conexÃ£o Telegram API: {hexc.Message}";
            _logger.LogError(hexc, msg);
            return new TelegramConnectResult(false, null, msg);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao conectar Telegram Bot API");
            return new TelegramConnectResult(false, null, $"Erro: {ex.Message}");
        }
    }
}

