using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppOutboundPublisher
{
    Task PublishAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken);
}
