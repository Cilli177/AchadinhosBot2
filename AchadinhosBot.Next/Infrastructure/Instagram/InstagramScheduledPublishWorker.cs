using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramScheduledPublishWorker : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<InstagramScheduledPublishWorker> _logger;

    public InstagramScheduledPublishWorker(
        IServiceProvider serviceProvider,
        ILogger<InstagramScheduledPublishWorker> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Instagram Scheduled Publish Worker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var publishStore = scope.ServiceProvider.GetRequiredService<IInstagramPublishStore>();
                var publishService = scope.ServiceProvider.GetRequiredService<IInstagramPublishService>();

                var drafts = await publishStore.ListAsync(stoppingToken);
                var dueDrafts = drafts.Where(d => 
                    d.Status == "scheduled" && 
                    d.ScheduledFor.HasValue && 
                    d.ScheduledFor.Value <= DateTimeOffset.UtcNow).ToList();

                foreach (var draft in dueDrafts)
                {
                    _logger.LogInformation("Processing scheduled draft {DraftId} for {ProductName}", draft.Id, draft.ProductName);
                    
                    // Mark as publishing to avoid picking it up again in parallel if something delays
                    draft.Status = "publishing";
                    await publishStore.UpdateAsync(draft, stoppingToken);

                    var result = await publishService.QueuePublishAsync(draft.Id, "system_scheduler", stoppingToken);
                    if (!result.Accepted)
                    {
                        _logger.LogWarning("Failed to queue scheduled draft {DraftId}: {Error}", draft.Id, result.Error);
                        draft.Status = "failed_scheduling";
                        draft.Error = result.Error;
                        await publishStore.UpdateAsync(draft, stoppingToken);
                    }
                    else
                    {
                        // Queued successfully. The actual publisher handles updating to 'published' or 'failed'.
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred executing scheduled publish worker.");
            }

            // Wait 1 minute before checking again
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}
