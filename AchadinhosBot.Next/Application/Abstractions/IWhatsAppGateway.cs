namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppGateway
{
    Task<WhatsAppConnectResult> ConnectAsync(CancellationToken cancellationToken);
}

public sealed record WhatsAppConnectResult(bool Success, string? QrCodeBase64, string? Message);
