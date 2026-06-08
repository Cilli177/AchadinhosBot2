using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Infrastructure.PriceWatch;

public sealed class PriceWatchWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PriceWatchWorker> _logger;

    public PriceWatchWorker(IServiceScopeFactory scopeFactory, ILogger<PriceWatchWorker> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<PriceWatchService>();
                var results = await service.RunDueAsync(20, stoppingToken);
                if (results.Count > 0)
                {
                    _logger.LogInformation(
                        "Radar de Preco processou {Count} alertas. Enviados={Sent} Revisao={Review}",
                        results.Count,
                        results.Count(x => x.Sent),
                        results.Count(x => x.ReviewCreated));
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha no worker do Radar de Preco.");
            }

            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}
