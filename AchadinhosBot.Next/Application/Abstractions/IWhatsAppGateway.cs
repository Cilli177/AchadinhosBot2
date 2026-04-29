namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppGateway
{
    Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken);
        Task<IReadOnlyList<WhatsAppInstanceInfo>> FetchInstancesAsync(CancellationToken cancellationToken);
    Task<WhatsAppConnectResult> TestConnectionAsync(string? instanceName, CancellationToken cancellationToken);
    Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken);
    Task<WhatsAppConnectionSnapshot> GetConnectionSnapshotAsync(string? instanceName, CancellationToken cancellationToken);
    Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> UpdateProfilePictureAsync(string? instanceName, string picture, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken);
    Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken);
}

public sealed record WhatsAppConnectResult(bool Success, string? QrCodeBase64, string? Message);
public sealed record WhatsAppInstanceResult(bool Success, string? QrCodeBase64, string? Message);
public sealed record WhatsAppConnectionSnapshot(bool Connected, string? State, string? QrCodeBase64, string? Message);
public sealed record WhatsAppSendResult(bool Success, string? Message);

public sealed record WhatsAppGroupInfo(string Id, string Name, int ParticipantsCount, string Type);
public sealed record WhatsAppInstanceInfo(string Name, string State);
