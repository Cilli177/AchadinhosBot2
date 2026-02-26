using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramAlertSender
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TelegramOptions _telegramOptions;
    private readonly ILogger<TelegramAlertSender> _logger;

    public TelegramAlertSender(
        IHttpClientFactory httpClientFactory,
        IOptions<TelegramOptions> telegramOptions,
        ILogger<TelegramAlertSender> logger)
    {
        _httpClientFactory = httpClientFactory;
        _telegramOptions = telegramOptions.Value;
        _logger = logger;
    }

    public async Task<bool> SendAsync(long chatId, string text, CancellationToken ct)
    {
        if (chatId == 0)
        {
            _logger.LogWarning("TelegramAlertSender: chatId invalido para envio de alerta.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(_telegramOptions.BotToken))
        {
            _logger.LogWarning("TelegramAlertSender: BotToken nao configurado.");
            return false;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var url = $"https://api.telegram.org/bot{_telegramOptions.BotToken}/sendMessage";
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            var payload = JsonSerializer.Serialize(new
            {
                chat_id = chatId,
                text
            });
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

            using var response = await client.SendAsync(request, ct);
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("TelegramAlertSender: falha ao enviar alerta. Status={Status} Body={Body}", (int)response.StatusCode, body);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TelegramAlertSender: erro ao enviar alerta.");
            return false;
        }
    }
}
