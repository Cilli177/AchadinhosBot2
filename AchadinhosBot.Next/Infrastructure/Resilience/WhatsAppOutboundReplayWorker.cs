using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class WhatsAppOutboundReplayWorker : BackgroundService
{
    private const string WorkerName = nameof(WhatsAppOutboundReplayWorker);
    private readonly IWhatsAppOutboundOutboxStore _outboxStore;
    private readonly IWhatsAppOutboundPublisher _publisher;
    private readonly MessagingOptions _options;
    private readonly WorkerActivityTracker _workerActivityTracker;

    public WhatsAppOutboundReplayWorker(
        IWhatsAppOutboundOutboxStore outboxStore,
        IWhatsAppOutboundPublisher publisher,
        IOptions<MessagingOptions> options,
        WorkerActivityTracker workerActivityTracker)
    {
        _outboxStore = outboxStore;
        _publisher = publisher;
        _options = options.Value;
        _workerActivityTracker = workerActivityTracker;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _workerActivityTracker.MarkStarted(WorkerName);
        await FlushAsync(stoppingToken);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(5, _options.OutboxReplayIntervalSeconds)));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await FlushAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task FlushAsync(CancellationToken cancellationToken)
    {
        var pending = await _outboxStore.ListPendingAsync(cancellationToken);
        if (pending.Count == 0)
        {
            _workerActivityTracker.MarkSuccess(WorkerName);
            return;
        }

        foreach (var command in pending.Take(Math.Max(1, _options.OutboxBatchSize)))
        {
            try
            {
                await _publisher.PublishAsync(command, cancellationToken);
                await _outboxStore.DeleteAsync(command.MessageId, cancellationToken);
            }
            catch (Exception ex)
            {
                _workerActivityTracker.MarkFailure(WorkerName, ex);
                break;
            }
        }

        _workerActivityTracker.MarkSuccess(WorkerName);
    }
}
