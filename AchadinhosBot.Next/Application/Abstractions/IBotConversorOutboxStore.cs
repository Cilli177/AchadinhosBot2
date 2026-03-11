using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IBotConversorOutboxStore
{
    Task SaveAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken);
    Task<IReadOnlyList<ProcessBotConversorWebhookCommand>> ListPendingAsync(CancellationToken cancellationToken);
    Task DeleteAsync(string messageId, CancellationToken cancellationToken);
}
