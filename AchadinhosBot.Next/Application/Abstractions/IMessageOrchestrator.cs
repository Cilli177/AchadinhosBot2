namespace AchadinhosBot.Next.Application.Abstractions;

public interface IMessageOrchestrator
{
    Task<MessageEnqueueResult> EnqueueBotConversorAsync(
        string body,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken);
}

public sealed record MessageEnqueueResult(
    string MessageId,
    bool Accepted,
    bool PersistedLocally,
    string Mode,
    string? Error);
