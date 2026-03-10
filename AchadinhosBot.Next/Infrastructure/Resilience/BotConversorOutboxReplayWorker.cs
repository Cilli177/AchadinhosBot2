using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class BotConversorOutboxReplayWorker : BackgroundService
{
    private readonly IBotConversorOutboxStore _outboxStore;
    private readonly IBotConversorQueuePublisher _publisher;
    private readonly MessagingOptions _options;
    private readonly ILogger<BotConversorOutboxReplayWorker> _logger;

    public BotConversorOutboxReplayWorker(
        IBotConversorOutboxStore outboxStore,
        IBotConversorQueuePublisher publisher,
        IOptions<MessagingOptions> options,
        ILogger<BotConversorOutboxReplayWorker> logger)
    {
        _outboxStore = outboxStore;
        _publisher = publisher;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await FlushPendingAsync(stoppingToken);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(5, _options.OutboxReplayIntervalSeconds)));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await FlushPendingAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Host is shutting down.
        }
    }

    private async Task FlushPendingAsync(CancellationToken cancellationToken)
    {
        var pending = await _outboxStore.ListPendingAsync(cancellationToken);
        if (pending.Count == 0)
        {
            return;
        }

        foreach (var command in pending.Take(Math.Max(1, _options.OutboxBatchSize)))
        {
            try
            {
                await _publisher.PublishAsync(command, cancellationToken);
                await _outboxStore.DeleteAsync(command.MessageId, cancellationToken);
                _logger.LogInformation("Mensagem {MessageId} reenfileirada do outbox local para o RabbitMQ.", command.MessageId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Falha ao reenfileirar mensagem {MessageId} do outbox local. Nova tentativa ocorrera depois.",
                    command.MessageId);
                break;
            }
        }
    }
}
