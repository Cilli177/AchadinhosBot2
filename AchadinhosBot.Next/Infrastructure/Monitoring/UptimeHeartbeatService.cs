using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Telegram;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Text;

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
    private bool _recoveryAlertSent;
    private int _consecutiveRecoverySuccesses;

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
                _recoveryAlertSent = false;
                _consecutiveRecoverySuccesses = 0;

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
                _recoveryAlertSent = false;
                _consecutiveRecoverySuccesses = 0;

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
            // Se estava fora de serviço, incrementa contador de sucessos
            if (_outageAlertSent && _consecutiveRecoverySuccesses < 2)
            {
                _consecutiveRecoverySuccesses++;
                _logger.LogInformation("Heartbeat recuperando: {SuccessCount}/2 tentativas bem-sucedidas", _consecutiveRecoverySuccesses);
            }

            // Só confirma recuperação após 2 sucessos consecutivos (evita falsos positivos)
            if (_outageAlertSent && !_recoveryAlertSent && _consecutiveRecoverySuccesses >= 2 && options.RecoveryAlertEnabled)
            {
                var message = BuildOnlineMessage();
                await SendAlertsAsync(options, message, stoppingToken);
                _recoveryAlertSent = true;
                _logger.LogInformation("Sistema confirmado como ONLINE após recuperação bem-sucedida");
            }

            _consecutiveFailures = 0;
            return;
        }

        // Se estava em recuperação, reseta o contador
        if (_consecutiveRecoverySuccesses > 0)
        {
            _logger.LogWarning("Heartbeat falhou durante recuperação. Resetando contador de sucessos");
            _consecutiveRecoverySuccesses = 0;
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

        var sent = await SendAlertsAsync(options, BuildOutageMessage(_consecutiveFailures), stoppingToken);
        if (sent)
        {
            _outageAlertSent = true;
            _consecutiveRecoverySuccesses = 0;
            _recoveryAlertSent = false;
        }
    }

    private async Task<bool> SendAlertsAsync(HeartbeatOptions options, string message, CancellationToken ct)
    {
        var telegramSent = await SendTelegramAlertAsync(options, message, ct);
        var ntfySent = await SendNtfyAlertAsync(options, message, ct);
        return telegramSent || ntfySent;
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

    private async Task<bool> SendNtfyAlertAsync(HeartbeatOptions options, string message, CancellationToken ct)
    {
        if (!options.NtfyAlertEnabled)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(options.NtfyTopicUrl))
        {
            _logger.LogWarning("Heartbeat ntfy alert habilitado, mas Heartbeat:NtfyTopicUrl nao foi configurado.");
            return false;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Post, options.NtfyTopicUrl);
            request.Content = new StringContent(message, Encoding.UTF8, "text/plain");
            request.Headers.TryAddWithoutValidation("Title", options.NtfyTitle);

            if (!string.IsNullOrWhiteSpace(options.NtfyPriority))
            {
                request.Headers.TryAddWithoutValidation("Priority", options.NtfyPriority);
            }

            if (!string.IsNullOrWhiteSpace(options.NtfyTags))
            {
                request.Headers.TryAddWithoutValidation("Tags", options.NtfyTags);
            }

            if (!string.IsNullOrWhiteSpace(options.PingUrl))
            {
                request.Headers.TryAddWithoutValidation("Click", options.PingUrl);
            }

            if (!string.IsNullOrWhiteSpace(options.NtfyAccessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.NtfyAccessToken);
            }

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(ct);
                _logger.LogWarning(
                    "Falha ao enviar alerta no ntfy. Status={StatusCode} Body={Body}",
                    (int)response.StatusCode,
                    Truncate(body, 300));
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro ao enviar alerta de heartbeat no ntfy.");
            return false;
        }
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

    private static string BuildOnlineMessage()
    {
        var ts = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
        return $"✅ SISTEMA ONLINE: AchadinhosBot recuperou após queda. Sistema operacional e respondendo normalmente. Horario: {ts}";
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
