using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Catalog;

public sealed class CatalogPriceRefreshWorker : BackgroundService
{
    // Roda a cada 1 minuto para processar retries rápidos (5 min / 20 min).
    // O ciclo padrão de 12h é controlado internamente pela store via UpdatedAt.
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(30);

    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<CatalogPriceRefreshWorker> _logger;

    public CatalogPriceRefreshWorker(
        IServiceProvider serviceProvider,
        ILogger<CatalogPriceRefreshWorker> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CatalogPriceRefreshWorker started. Fast-retry interval: {Interval}m, standard cycle: 12h", Interval.TotalMinutes);

        await Task.Delay(InitialDelay, stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var store = _serviceProvider.GetRequiredService<ICatalogOfferStore>();
                var refreshed = await store.RefreshPricesAsync(stoppingToken);
                _logger.LogInformation("Catalog price refresh completed: {Count} items updated.", refreshed);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during catalog price refresh.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }
}
