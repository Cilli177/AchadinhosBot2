using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class WhatsAppOutboundReplayWorker : BackgroundService
{
    private readonly IWhatsAppOutboundOutboxStore _outboxStore;
    private readonly IWhatsAppOutboundPublisher _publisher;
    private readonly MessagingOptions _options;

    public WhatsAppOutboundReplayWorker(
        IWhatsAppOutboundOutboxStore outboxStore,
        IWhatsAppOutboundPublisher publisher,
        IOptions<MessagingOptions> options)
    {
        _outboxStore = outboxStore;
        _publisher = publisher;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
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
        foreach (var command in pending.Take(Math.Max(1, _options.OutboxBatchSize)))
        {
            try
            {
                await _publisher.PublishAsync(command, cancellationToken);
                await _outboxStore.DeleteAsync(command.MessageId, cancellationToken);
            }
            catch
            {
                break;
            }
        }
    }
}
