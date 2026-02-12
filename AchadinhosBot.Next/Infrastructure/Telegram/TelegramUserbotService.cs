namespace AchadinhosBot.Next.Infrastructure.Telegram;

public sealed class TelegramUserbotService : BackgroundService
{
    private readonly ILogger<TelegramUserbotService> _logger;

    public TelegramUserbotService(ILogger<TelegramUserbotService> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("TelegramUserbotService em modo mock para projeto isolado.");
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}
