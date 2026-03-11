using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramOutboundPublisher
{
    Task PublishAsync(PublishInstagramPostCommand command, CancellationToken cancellationToken);
    Task PublishAsync(ReplyInstagramCommentCommand command, CancellationToken cancellationToken);
    Task PublishAsync(SendInstagramDirectMessageCommand command, CancellationToken cancellationToken);
}
