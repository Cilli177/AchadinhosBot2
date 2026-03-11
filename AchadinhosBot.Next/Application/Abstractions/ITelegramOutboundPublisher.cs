using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramOutboundPublisher
{
    Task PublishAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken);
}
