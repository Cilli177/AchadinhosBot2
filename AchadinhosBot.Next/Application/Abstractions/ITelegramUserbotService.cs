namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramUserbotService
{
    Task<IReadOnlyList<TelegramUserbotChat>> GetDialogsAsync(CancellationToken cancellationToken);
    Task<bool> RefreshDialogsAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<TelegramUserbotOfferMessage>> ListRecentOffersAsync(IReadOnlyCollection<long> sourceChatIds, int perChatLimit, CancellationToken cancellationToken);
    Task<TelegramUserbotReplayResult> ReplayRecentOffersToWhatsAppAsync(long sourceChatId, int count, bool allowOfficialDestination, CancellationToken cancellationToken);
    Task<TelegramUserbotAuthUpdateResult> UpdateRuntimeAuthAsync(TelegramUserbotAuthUpdateRequest request, CancellationToken cancellationToken);
    bool IsReady { get; }
}

public sealed record TelegramUserbotChat(long Id, string Title, string Type);
public sealed record TelegramUserbotOfferMessage(
    long ChatId,
    string ChatTitle,
    string MessageId,
    DateTimeOffset CreatedAtUtc,
    string Text,
    string MediaKind,
    string? MediaUrl);
public sealed record TelegramUserbotReplayResult(
    bool Success,
    string Message,
    long SourceChatId,
    int Requested,
    int Loaded,
    int Replayed,
    int Failed);

public sealed record TelegramUserbotAuthUpdateRequest(
    string? PhoneNumber,
    string? VerificationCode,
    string? Password,
    bool ForceReconnect);

public sealed record TelegramUserbotAuthUpdateResult(
    bool Success,
    bool ReconnectRequested,
    bool HasPhoneNumber,
    bool HasVerificationCode,
    bool HasPassword,
    string Message);
