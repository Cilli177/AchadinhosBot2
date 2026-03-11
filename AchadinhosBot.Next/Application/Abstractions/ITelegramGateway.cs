namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramGateway
{
    Task<TelegramConnectResult> ConnectAsync(string? botToken, CancellationToken cancellationToken);
    Task<TelegramSendResult> SendTextAsync(string? botToken, long chatId, string text, CancellationToken cancellationToken);
    Task<TelegramSendResult> SendPhotoAsync(string? botToken, long chatId, string photoUrl, string? caption, CancellationToken cancellationToken);
}

public sealed record TelegramConnectResult(bool Success, string? Username, string? Message);
