using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using MassTransit;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class RabbitMqBotConversorQueuePublisher : IBotConversorQueuePublisher
{
    private readonly IBus _publishEndpoint;

    public RabbitMqBotConversorQueuePublisher(IBus publishEndpoint)
    {
        _publishEndpoint = publishEndpoint;
    }

    public Task PublishAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken)
    {
        return _publishEndpoint.Publish(command, publishContext =>
        {
            if (Guid.TryParse(command.MessageId, out var messageGuid))
            {
                publishContext.MessageId = messageGuid;
            }

            publishContext.Headers.Set("bot-conversor-message-id", command.MessageId);
            publishContext.Headers.Set("bot-conversor-source", command.Source);
        }, cancellationToken);
    }
}
