using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class BotConversorMessageOrchestrator : IMessageOrchestrator
{
    private readonly IBotConversorQueuePublisher _publisher;
    private readonly IBotConversorOutboxStore _outboxStore;
    private readonly ILogger<BotConversorMessageOrchestrator> _logger;

    public BotConversorMessageOrchestrator(
        IBotConversorQueuePublisher publisher,
        IBotConversorOutboxStore outboxStore,
        ILogger<BotConversorMessageOrchestrator> logger)
    {
        _publisher = publisher;
        _outboxStore = outboxStore;
        _logger = logger;
    }

    public async Task<MessageEnqueueResult> EnqueueBotConversorAsync(
        string body,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        var command = new ProcessBotConversorWebhookCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            Body = body ?? string.Empty,
            Headers = headers
                .Where(item => !string.IsNullOrWhiteSpace(item.Key))
                .ToDictionary(item => item.Key, item => item.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase),
            ReceivedAtUtc = DateTimeOffset.UtcNow,
            Source = "webhook/bot-conversor"
        };

        try
        {
            await _publisher.PublishAsync(command, cancellationToken);
            return new MessageEnqueueResult(command.MessageId, true, false, "rabbitmq", null);
        }
        catch (Exception publishException)
        {
            _logger.LogWarning(
                publishException,
                "Falha ao publicar mensagem {MessageId} no RabbitMQ. Persistindo em outbox local.",
                command.MessageId);

            try
            {
                await _outboxStore.SaveAsync(command, cancellationToken);
                return new MessageEnqueueResult(command.MessageId, true, true, "local-outbox", publishException.Message);
            }
            catch (Exception outboxException)
            {
                _logger.LogError(
                    outboxException,
                    "Falha ao persistir mensagem {MessageId} no outbox local.",
                    command.MessageId);

                return new MessageEnqueueResult(
                    command.MessageId,
                    false,
                    false,
                    "failed",
                    $"{publishException.Message} | {outboxException.Message}");
            }
        }
    }
}
