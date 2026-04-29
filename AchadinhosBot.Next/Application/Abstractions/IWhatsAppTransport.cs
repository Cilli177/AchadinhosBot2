namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppTransport
{
    Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken);
    Task<WhatsAppConnectResult> TestConnectionAsync(string? instanceName, CancellationToken cancellationToken)
        => ConnectAsync(instanceName, cancellationToken);
    Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken);
    Task<WhatsAppConnectionSnapshot> GetConnectionSnapshotAsync(string? instanceName, CancellationToken cancellationToken)
        => Task.FromResult(new WhatsAppConnectionSnapshot(false, null, null, "Snapshot nao implementado."));
    Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken);
    Task<WhatsAppSendResult> UpdateProfilePictureAsync(string? instanceName, string picture, CancellationToken cancellationToken)
        => Task.FromResult(new WhatsAppSendResult(false, "Atualizacao de foto nao implementada."));
    Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken);
    Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken)
        => Task.FromResult(new WhatsAppSendResult(false, "Adicao de participantes nao implementada."));
    Task<IReadOnlyList<WhatsAppInstanceInfo>> FetchInstancesAsync(CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyList<WhatsAppInstanceInfo>>(Array.Empty<WhatsAppInstanceInfo>());
}
