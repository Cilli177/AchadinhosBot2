using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramBotApiGateway : ITelegramGateway, ITelegramTransport
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
        var tokenToUse = ResolveBotToken(botToken);
        if (string.IsNullOrWhiteSpace(tokenToUse))
        {
            _logger.LogWarning("Telegram BotToken nao configurado");
            return new TelegramConnectResult(false, null, "BotToken nao configurado - verifique variavel TELEGRAM_BOT_TOKEN no .env");
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
                _logger.LogWarning("Token Telegram invalido ou expirado");
                return new TelegramConnectResult(false, null, "Token invalido ou expirado");
            }

            var username = root.GetProperty("result").GetProperty("username").GetString();
            PersistBotToken(tokenToUse);
            _logger.LogInformation("Telegram Bot conectado: @{Username}", username);
            return new TelegramConnectResult(true, username, "Telegram conectado com sucesso");
        }
        catch (HttpRequestException hexc)
        {
            var msg = $"Erro de conexao Telegram API: {hexc.Message}";
            _logger.LogError(hexc, msg);
            return new TelegramConnectResult(false, null, msg);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao conectar Telegram Bot API");
            return new TelegramConnectResult(false, null, $"Erro: {ex.Message}");
        }
    }

    public async Task<TelegramSendResult> SendTextAsync(string? botToken, long chatId, string text, CancellationToken cancellationToken)
    {
        var tokenToUse = ResolveBotToken(botToken);
        if (string.IsNullOrWhiteSpace(tokenToUse))
        {
            return new TelegramSendResult(false, "BotToken nao configurado.");
        }

        try
        {
            var client = _factory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://api.telegram.org/bot{tokenToUse}/sendMessage");
            request.Content = new StringContent(
                JsonSerializer.Serialize(new
                {
                    chat_id = chatId,
                    text
                }),
                Encoding.UTF8,
                "application/json");

            using var response = await client.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return new TelegramSendResult(true, "Mensagem enviada.");
            }

            _logger.LogWarning("Falha ao enviar texto Telegram. Status={Status} Body={Body}", response.StatusCode, body);
            return new TelegramSendResult(false, $"Falha ao enviar mensagem: {response.StatusCode}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao enviar texto Telegram.");
            return new TelegramSendResult(false, $"Erro: {ex.Message}");
        }
    }

    public async Task<TelegramSendResult> SendPhotoAsync(string? botToken, long chatId, string photoUrl, string? caption, CancellationToken cancellationToken)
    {
        var tokenToUse = ResolveBotToken(botToken);
        if (string.IsNullOrWhiteSpace(tokenToUse))
        {
            return new TelegramSendResult(false, "BotToken nao configurado.");
        }

        if (string.IsNullOrWhiteSpace(photoUrl))
        {
            return new TelegramSendResult(false, "Photo URL invalida.");
        }

        try
        {
            var client = _factory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://api.telegram.org/bot{tokenToUse}/sendPhoto");
            request.Content = new StringContent(
                JsonSerializer.Serialize(new
                {
                    chat_id = chatId,
                    photo = photoUrl,
                    caption = caption ?? string.Empty
                }),
                Encoding.UTF8,
                "application/json");

            using var response = await client.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return new TelegramSendResult(true, "Imagem enviada.");
            }

            _logger.LogWarning("Falha ao enviar foto Telegram. Status={Status} Body={Body}", response.StatusCode, body);
            return new TelegramSendResult(false, $"Falha ao enviar foto: {response.StatusCode}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao enviar foto Telegram.");
            return new TelegramSendResult(false, $"Erro: {ex.Message}");
        }
    }

    private string? ResolveBotToken(string? botToken)
    {
        return NormalizeBotToken(botToken)
            ?? NormalizeBotToken(_options.BotToken)
            ?? LoadPersistedBotToken();
    }

    private static string? NormalizeBotToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var normalized = token.Trim();
        if (normalized.StartsWith("bot", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[3..].Trim();
        }

        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private string GetTokenFilePath()
    {
        var configured = Environment.GetEnvironmentVariable("TELEGRAM__BOTTOKEN_FILE");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim();
        }

        var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
        return Path.Combine(dataDir, "telegram-bot-token.txt");
    }

    private string? LoadPersistedBotToken()
    {
        try
        {
            var path = GetTokenFilePath();
            if (!File.Exists(path))
            {
                return null;
            }

            var raw = File.ReadAllText(path);
            return NormalizeBotToken(raw);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao ler token persistido do Telegram bot.");
            return null;
        }
    }

    private void PersistBotToken(string token)
    {
        try
        {
            var path = GetTokenFilePath();
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(path, token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao persistir token do Telegram bot.");
        }
    }
}
