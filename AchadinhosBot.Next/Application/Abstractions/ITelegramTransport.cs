namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramTransport
{
    Task<TelegramConnectResult> ConnectAsync(string? botToken, CancellationToken cancellationToken);
    Task<TelegramSendResult> SendTextAsync(string? botToken, long chatId, string text, CancellationToken cancellationToken);
    Task<TelegramSendResult> SendPhotoAsync(string? botToken, long chatId, string photoUrl, string? caption, CancellationToken cancellationToken);
}

public sealed class TelegramSendResult
{
    public TelegramSendResult(bool success, string? message)
    {
        Success = success;
        Message = message;
    }

    public bool Success { get; }

    public string? Message { get; }
}
