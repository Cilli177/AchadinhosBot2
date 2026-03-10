using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using MassTransit;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class RabbitMqTelegramOutboundPublisher : ITelegramOutboundPublisher
{
    private readonly IBus _publishEndpoint;

    public RabbitMqTelegramOutboundPublisher(IBus publishEndpoint)
    {
        _publishEndpoint = publishEndpoint;
    }

    public Task PublishAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken)
    {
        return _publishEndpoint.Publish(command, context =>
        {
            if (Guid.TryParse(command.MessageId, out var guid))
            {
                context.MessageId = guid;
            }

            context.Headers.Set("outbound-channel", "telegram");
            context.Headers.Set("dedupe-key", command.DeduplicationKey);
        }, cancellationToken);
    }
}
