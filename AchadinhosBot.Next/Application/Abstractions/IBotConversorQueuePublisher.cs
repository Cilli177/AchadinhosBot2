using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IBotConversorQueuePublisher
{
    Task PublishAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken);
}
