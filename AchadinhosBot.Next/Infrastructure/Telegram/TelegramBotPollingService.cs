namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramBotPollingService : BackgroundService
{
    private readonly ILogger<TelegramBotPollingService> _logger;

    public TelegramBotPollingService(ILogger<TelegramBotPollingService> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("TelegramBotPollingService em modo mock para projeto isolado.");
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}
