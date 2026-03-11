using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class QueuedWhatsAppGateway : IWhatsAppGateway
{
    private readonly IWhatsAppTransport _transport;
    private readonly IWhatsAppOutboundPublisher _publisher;
    private readonly IWhatsAppOutboundOutboxStore _outboxStore;
    private readonly ILogger<QueuedWhatsAppGateway> _logger;

    public QueuedWhatsAppGateway(
        IWhatsAppTransport transport,
        IWhatsAppOutboundPublisher publisher,
        IWhatsAppOutboundOutboxStore outboxStore,
        ILogger<QueuedWhatsAppGateway> logger)
    {
        _transport = transport;
        _publisher = publisher;
        _outboxStore = outboxStore;
        _logger = logger;
    }

    public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken)
        => _transport.ConnectAsync(instanceName, cancellationToken);

    public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken)
        => _transport.CreateInstanceAsync(instanceName, cancellationToken);

    public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken)
        => _transport.GetGroupsAsync(instanceName, cancellationToken);

    public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken)
        => _transport.DeleteMessageAsync(instanceName, chatId, messageId, isGroup, cancellationToken);

    public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken)
        => QueueAsync(new SendWhatsAppMessageCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            DeduplicationKey = OutboundMessageFingerprint.Compute("wa", "text", instanceName, to, text),
            Kind = "text",
            InstanceName = instanceName,
            To = to,
            Text = text,
            TextFallbackAllowed = false
        }, cancellationToken);

    public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken)
        => QueueAsync(new SendWhatsAppMessageCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            DeduplicationKey = OutboundMessageFingerprint.Compute("wa", "image-bytes", instanceName, to, caption, mimeType, Convert.ToBase64String(imageBytes)),
            Kind = "image-bytes",
            InstanceName = instanceName,
            To = to,
            Text = caption,
            MediaBase64 = Convert.ToBase64String(imageBytes),
            MimeType = mimeType,
            TextFallbackAllowed = !string.IsNullOrWhiteSpace(caption)
        }, cancellationToken);

    public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken)
        => QueueAsync(new SendWhatsAppMessageCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            DeduplicationKey = OutboundMessageFingerprint.Compute("wa", "image-url", instanceName, to, caption, mimeType, mediaUrl),
            Kind = "image-url",
            InstanceName = instanceName,
            To = to,
            Text = caption,
            MediaUrl = mediaUrl,
            MimeType = mimeType,
            FileName = fileName,
            TextFallbackAllowed = !string.IsNullOrWhiteSpace(caption)
        }, cancellationToken);

    private async Task<WhatsAppSendResult> QueueAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken)
    {
        try
        {
            await _publisher.PublishAsync(command, cancellationToken);
            return new WhatsAppSendResult(true, $"Mensagem enfileirada ({command.Kind}).");
        }
        catch (Exception publishException)
        {
            _logger.LogWarning(publishException, "Falha ao publicar outbound WhatsApp {MessageId}. Persistindo em outbox local.", command.MessageId);
            try
            {
                await _outboxStore.SaveAsync(command, cancellationToken);
                return new WhatsAppSendResult(true, "Mensagem persistida em outbox local do WhatsApp.");
            }
            catch (Exception outboxException)
            {
                _logger.LogError(outboxException, "Falha ao persistir outbound WhatsApp {MessageId}.", command.MessageId);
                return new WhatsAppSendResult(false, $"{publishException.Message} | {outboxException.Message}");
            }
        }
    }
}
