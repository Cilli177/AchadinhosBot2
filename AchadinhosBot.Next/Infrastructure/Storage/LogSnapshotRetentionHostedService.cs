namespace AchadinhosBot.Next.Infrastructure.Storage;

internal sealed class LogSnapshotRetentionHostedService(LogSnapshotRetentionService retention, ILogger<LogSnapshotRetentionHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await retention.PruneAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogError(exception, "Log snapshot retention failed."); }
            await Task.Delay(TimeSpan.FromDays(1), stoppingToken);
        }
    }
}
