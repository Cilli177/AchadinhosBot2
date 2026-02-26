using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramAutoPilotWorker : BackgroundService
{
    private readonly ISettingsStore _settingsStore;
    private readonly IInstagramAutoPilotService _autoPilotService;
    private readonly ILogger<InstagramAutoPilotWorker> _logger;

    public InstagramAutoPilotWorker(
        ISettingsStore settingsStore,
        IInstagramAutoPilotService autoPilotService,
        ILogger<InstagramAutoPilotWorker> logger)
    {
        _settingsStore = settingsStore;
        _autoPilotService = autoPilotService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = await _settingsStore.GetAsync(stoppingToken);
                var insta = settings.InstagramPublish ?? new InstagramPublishSettings();
                if (!insta.AutoPilotEnabled)
                {
                    await SafeDelay(TimeSpan.FromMinutes(2), stoppingToken);
                    continue;
                }

                var interval = TimeSpan.FromMinutes(Math.Clamp(insta.AutoPilotIntervalMinutes, 15, 1440));
                var request = new InstagramAutoPilotRunRequest
                {
                    TopCount = insta.AutoPilotTopCount,
                    LookbackHours = insta.AutoPilotLookbackHours,
                    RepeatWindowHours = insta.AutoPilotRepeatWindowHours,
                    SendForApproval = insta.AutoPilotSendForApproval,
                    ApprovalChannel = insta.AutoPilotApprovalChannel,
                    ApprovalTelegramChatId = insta.AutoPilotApprovalTelegramChatId,
                    ApprovalWhatsAppGroupId = insta.AutoPilotApprovalWhatsAppGroupId,
                    ApprovalWhatsAppInstanceName = insta.AutoPilotApprovalWhatsAppInstanceName,
                    DryRun = false
                };

                var result = await _autoPilotService.RunNowAsync(request, stoppingToken);
                _logger.LogInformation(
                    "Instagram autopilot run: success={Success} selected={Selected} drafts={Drafts} approvalSent={ApprovalSent} message={Message}",
                    result.Success,
                    result.SelectedCount,
                    result.DraftsCreated,
                    result.ApprovalSent,
                    result.Message);

                await SafeDelay(interval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Instagram autopilot worker iteration failed.");
                await SafeDelay(TimeSpan.FromMinutes(2), stoppingToken);
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
