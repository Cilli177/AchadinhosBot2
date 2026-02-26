using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Telegram;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Monitoring;

public sealed class UptimeHeartbeatService : BackgroundService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsMonitor<HeartbeatOptions> _optionsMonitor;
    private readonly IOptions<TelegramOptions> _telegramOptions;
    private readonly TelegramAlertSender _telegramAlertSender;
    private readonly ILogger<UptimeHeartbeatService> _logger;
    private int _consecutiveFailures;
    private bool _outageAlertSent;

    public UptimeHeartbeatService(
        IHttpClientFactory httpClientFactory,
        IOptionsMonitor<HeartbeatOptions> optionsMonitor,
        IOptions<TelegramOptions> telegramOptions,
        TelegramAlertSender telegramAlertSender,
        ILogger<UptimeHeartbeatService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _optionsMonitor = optionsMonitor;
        _telegramOptions = telegramOptions;
        _telegramAlertSender = telegramAlertSender;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string mode = "init";

        while (!stoppingToken.IsCancellationRequested)
        {
            var options = _optionsMonitor.CurrentValue;
            var interval = TimeSpan.FromSeconds(Math.Clamp(options.IntervalSeconds, 15, 3600));

            if (!options.Enabled)
            {
                if (!string.Equals(mode, "disabled", StringComparison.Ordinal))
                {
                    mode = "disabled";
                    _logger.LogInformation("Heartbeat monitor desativado.");
                }

                _consecutiveFailures = 0;
                _outageAlertSent = false;

                await DelayAsync(interval, stoppingToken);
                continue;
            }

            if (string.IsNullOrWhiteSpace(options.PingUrl))
            {
                if (!string.Equals(mode, "missing-url", StringComparison.Ordinal))
                {
                    mode = "missing-url";
                    _logger.LogWarning("Heartbeat habilitado, mas Heartbeat:PingUrl nao foi configurado.");
                }

                _consecutiveFailures = 0;
                _outageAlertSent = false;

                await DelayAsync(interval, stoppingToken);
                continue;
            }

            if (!string.Equals(mode, "running", StringComparison.Ordinal))
            {
                mode = "running";
                _logger.LogInformation(
                    "Heartbeat monitor ativo. Interval={IntervalSeconds}s Url={PingUrl}",
                    (int)interval.TotalSeconds,
                    options.PingUrl);
            }

            var ok = await SendHeartbeatAsync(options, stoppingToken);
            await HandleAlertStateAsync(options, ok, stoppingToken);
            await DelayAsync(interval, stoppingToken);
        }
    }

    private async Task<bool> SendHeartbeatAsync(HeartbeatOptions options, CancellationToken stoppingToken)
    {
        var timeout = TimeSpan.FromSeconds(Math.Clamp(options.TimeoutSeconds, 2, 120));
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, options.PingUrl);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token);

            if (response.IsSuccessStatusCode)
            {
                if (options.LogSuccess)
                {
                    _logger.LogInformation("Heartbeat enviado com sucesso. Status={StatusCode}", (int)response.StatusCode);
                }

                return true;
            }

            var responseBody = await response.Content.ReadAsStringAsync(timeoutCts.Token);
            var compactBody = Truncate(responseBody, 300);
            _logger.LogWarning(
                "Falha no heartbeat. Status={StatusCode} Body={Body}",
                (int)response.StatusCode,
                compactBody);

            return false;
        }
        catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
        {
            _logger.LogWarning("Heartbeat timeout apos {TimeoutSeconds}s.", (int)timeout.TotalSeconds);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro ao enviar heartbeat.");
            return false;
        }
    }

    private async Task HandleAlertStateAsync(HeartbeatOptions options, bool heartbeatOk, CancellationToken stoppingToken)
    {
        if (heartbeatOk)
        {
            if (_outageAlertSent && options.RecoveryAlertEnabled)
            {
                await SendTelegramAlertAsync(options, BuildRecoveryMessage(), stoppingToken);
            }

            _consecutiveFailures = 0;
            _outageAlertSent = false;
            return;
        }

        _consecutiveFailures++;
        if (_outageAlertSent)
        {
            return;
        }

        var threshold = Math.Clamp(options.FailureAlertThreshold, 1, 30);
        if (_consecutiveFailures < threshold)
        {
            return;
        }

        var sent = await SendTelegramAlertAsync(options, BuildOutageMessage(_consecutiveFailures), stoppingToken);
        if (sent)
        {
            _outageAlertSent = true;
        }
    }

    private async Task<bool> SendTelegramAlertAsync(HeartbeatOptions options, string message, CancellationToken ct)
    {
        if (!options.TelegramAlertEnabled)
        {
            return false;
        }

        var chatId = options.TelegramAlertChatId != 0
            ? options.TelegramAlertChatId
            : _telegramOptions.Value.LogsChatId;

        if (chatId == 0)
        {
            _logger.LogWarning("Heartbeat Telegram alert habilitado, mas chat id nao configurado.");
            return false;
        }

        var sent = await _telegramAlertSender.SendAsync(chatId, message, ct);
        if (!sent)
        {
            _logger.LogWarning("Falha ao enviar alerta de heartbeat no Telegram.");
        }

        return sent;
    }

    private static string BuildOutageMessage(int failures)
    {
        var ts = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
        return $"ALERTA: heartbeat falhou {failures}x seguidas. Possivel indisponibilidade do robo. Horario: {ts}";
    }

    private static string BuildRecoveryMessage()
    {
        var ts = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
        return $"RECUPERADO: heartbeat voltou ao normal. Horario: {ts}";
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(delay, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // ignore graceful shutdown
        }
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
        {
            return value;
        }

        return $"{value[..maxLength]}...";
    }
}
