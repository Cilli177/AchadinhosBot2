using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Content;

public sealed class ContentCalendarWorker : BackgroundService
{
    private readonly ISettingsStore _settingsStore;
    private readonly ContentCalendarAutomationService _automationService;
    private readonly ILogger<ContentCalendarWorker> _logger;

    public ContentCalendarWorker(
        ISettingsStore settingsStore,
        ContentCalendarAutomationService automationService,
        ILogger<ContentCalendarWorker> logger)
    {
        _settingsStore = settingsStore;
        _automationService = automationService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = await _settingsStore.GetAsync(stoppingToken);
                var contentCalendar = settings.ContentCalendar ?? new ContentCalendarSettings();
                var delaySeconds = Math.Clamp(contentCalendar.PollIntervalSeconds, 15, 300);

                if (contentCalendar.Enabled)
                {
                    var summary = await _automationService.ProcessDueAsync(stoppingToken);
                    if (summary.TotalDue > 0)
                    {
                        _logger.LogInformation(
                            "Content calendar run: due={Due} processed={Processed} drafts={Drafts} published={Published} failed={Failed}",
                            summary.TotalDue,
                            summary.Processed,
                            summary.DraftsCreated,
                            summary.Published,
                            summary.Failed);
                    }
                }

                await SafeDelay(TimeSpan.FromSeconds(delaySeconds), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Content calendar worker iteration failed.");
                await SafeDelay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }
    }

    private static async Task SafeDelay(TimeSpan delay, CancellationToken ct)
    {
        try
        {
            await Task.Delay(delay, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }
}
