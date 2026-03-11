using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using MassTransit;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class RabbitMqInstagramOutboundPublisher : IInstagramOutboundPublisher
{
    private readonly IBus _bus;

    public RabbitMqInstagramOutboundPublisher(IBus bus)
    {
        _bus = bus;
    }

    public Task PublishAsync(PublishInstagramPostCommand command, CancellationToken cancellationToken)
        => PublishCoreAsync(command, "instagram-publish", command.DeduplicationKey, cancellationToken);

    public Task PublishAsync(ReplyInstagramCommentCommand command, CancellationToken cancellationToken)
        => PublishCoreAsync(command, "instagram-comment-reply", command.DeduplicationKey, cancellationToken);

    public Task PublishAsync(SendInstagramDirectMessageCommand command, CancellationToken cancellationToken)
        => PublishCoreAsync(command, "instagram-direct-message", command.DeduplicationKey, cancellationToken);

    private Task PublishCoreAsync<T>(T command, string channel, string dedupeKey, CancellationToken cancellationToken)
        where T : class
    {
        return _bus.Publish(command, context =>
        {
            var messageId = command switch
            {
                PublishInstagramPostCommand publish => publish.MessageId,
                ReplyInstagramCommentCommand reply => reply.MessageId,
                SendInstagramDirectMessageCommand dm => dm.MessageId,
                _ => null
            };

            if (Guid.TryParse(messageId, out var parsed))
            {
                context.MessageId = parsed;
            }

            context.Headers.Set("outbound-channel", channel);
            context.Headers.Set("dedupe-key", dedupeKey);
        }, cancellationToken);
    }
}
