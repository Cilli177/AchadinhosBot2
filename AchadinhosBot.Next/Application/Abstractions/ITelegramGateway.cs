namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramGateway
{
    Task<TelegramConnectResult> ConnectAsync(string? botToken, CancellationToken cancellationToken);
}

public sealed record TelegramConnectResult(bool Success, string? Username, string? Message);
