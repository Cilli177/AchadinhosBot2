using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppAdminAutomationWorker : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    private readonly WhatsAppAdminAutomationService _automationService;
    private readonly WhatsAppAutomationQueueService _queueService;
    private readonly ILogger<WhatsAppAdminAutomationWorker> _logger;

    public WhatsAppAdminAutomationWorker(
        WhatsAppAdminAutomationService automationService,
        WhatsAppAutomationQueueService queueService,
        ILogger<WhatsAppAdminAutomationWorker> logger)
    {
        _automationService = automationService;
        _queueService = queueService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WhatsAppAdminAutomationWorker iniciado. Intervalo: {Interval}", PollInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                while (!_queueService.GetState().Items.All(x => !string.Equals(x.Status, "queued", StringComparison.OrdinalIgnoreCase)))
                {
                    await _queueService.ProcessNextAsync(stoppingToken);
                    if (stoppingToken.IsCancellationRequested)
                    {
                        return;
                    }
                }

                await _automationService.ProcessDueSchedulesAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no loop principal das automacoes administrativas do WhatsApp");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }
}
