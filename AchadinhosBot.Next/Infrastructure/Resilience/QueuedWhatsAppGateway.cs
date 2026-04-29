using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class QueuedWhatsAppGateway : IWhatsAppGateway
{
    private readonly IWhatsAppTransport _transport;
    private readonly IWhatsAppOutboundPublisher _publisher;
    private readonly IWhatsAppOutboundOutboxStore _outboxStore;
    private readonly DeliverySafetyOptions _deliverySafetyOptions;
    private readonly ILogger<QueuedWhatsAppGateway> _logger;

    public QueuedWhatsAppGateway(
        IWhatsAppTransport transport,
        IWhatsAppOutboundPublisher publisher,
        IWhatsAppOutboundOutboxStore outboxStore,
        IOptions<DeliverySafetyOptions> deliverySafetyOptions,
        ILogger<QueuedWhatsAppGateway> logger)
    {
        _transport = transport;
        _publisher = publisher;
        _outboxStore = outboxStore;
        _deliverySafetyOptions = deliverySafetyOptions.Value;
        _logger = logger;
    }

    public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken)
        => _transport.ConnectAsync(instanceName, cancellationToken);

    public Task<WhatsAppConnectResult> TestConnectionAsync(string? instanceName, CancellationToken cancellationToken)
        => _transport.TestConnectionAsync(instanceName, cancellationToken);

    public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken)
        => _transport.CreateInstanceAsync(instanceName, cancellationToken);

    public Task<WhatsAppConnectionSnapshot> GetConnectionSnapshotAsync(string? instanceName, CancellationToken cancellationToken)
        => _transport.GetConnectionSnapshotAsync(instanceName, cancellationToken);

    public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken)
        => _transport.GetGroupsAsync(instanceName, cancellationToken);

    public Task<WhatsAppSendResult> UpdateProfilePictureAsync(string? instanceName, string picture, CancellationToken cancellationToken)
        => _transport.UpdateProfilePictureAsync(instanceName, picture, cancellationToken);

    public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken)
        => _transport.DeleteMessageAsync(instanceName, chatId, messageId, isGroup, cancellationToken);

    public Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken)
        => _transport.GetGroupParticipantsAsync(instanceName, groupId, cancellationToken);

    public Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken)
        => _transport.AddParticipantsAsync(instanceName, groupId, participantJids, cancellationToken);

        public Task<IReadOnlyList<WhatsAppInstanceInfo>> FetchInstancesAsync(CancellationToken cancellationToken)
            => _transport.FetchInstancesAsync(cancellationToken);

    public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken)
    {
        if (IsOfficialDestination(to))
        {
            _logger.LogWarning(
                "Envio WhatsApp texto bloqueado para grupo oficial. Instance={InstanceName} Destination={Destination}",
                instanceName,
                to);
            return Task.FromResult(new WhatsAppSendResult(false, "Grupo oficial exige imagem; envio de texto bloqueado."));
        }

        return QueueAsync(new SendWhatsAppMessageCommand
            {
                MessageId = Guid.NewGuid().ToString("N"),
                DeduplicationKey = OutboundMessageFingerprint.Compute("wa", "text", instanceName, to, text),
                Kind = "text",
                InstanceName = instanceName,
                To = to,
                Text = text,
                TextFallbackAllowed = false
            },
            cancellationToken);
    }

    public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken)
    {
        if (IsOfficialDestination(to) && (imageBytes is null || imageBytes.Length == 0))
        {
            _logger.LogWarning(
                "Envio WhatsApp imagem vazia bloqueado para grupo oficial. Instance={InstanceName} Destination={Destination}",
                instanceName,
                to);
            return Task.FromResult(new WhatsAppSendResult(false, "Grupo oficial exige imagem valida; envio sem foto bloqueado."));
        }

        var mediaBase64 = Convert.ToBase64String(imageBytes ?? Array.Empty<byte>());
        return QueueAsync(new SendWhatsAppMessageCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            DeduplicationKey = OutboundMessageFingerprint.Compute("wa", "image-bytes", instanceName, to, caption, mimeType, mediaBase64),
            Kind = "image-bytes",
            InstanceName = instanceName,
            To = to,
            Text = caption,
            MediaBase64 = mediaBase64,
            MimeType = mimeType,
            TextFallbackAllowed = !IsOfficialDestination(to) && !string.IsNullOrWhiteSpace(caption)
        }, cancellationToken);
    }

    public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken)
    {
        if (IsOfficialDestination(to) && string.IsNullOrWhiteSpace(mediaUrl))
        {
            _logger.LogWarning(
                "Envio WhatsApp imagem sem URL bloqueado para grupo oficial. Instance={InstanceName} Destination={Destination}",
                instanceName,
                to);
            return Task.FromResult(new WhatsAppSendResult(false, "Grupo oficial exige imagem valida; envio sem foto bloqueado."));
        }

        return QueueAsync(new SendWhatsAppMessageCommand
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
            TextFallbackAllowed = !IsOfficialDestination(to) && !string.IsNullOrWhiteSpace(caption)
        }, cancellationToken);
    }

    private bool IsOfficialDestination(string to)
    {
        if (string.IsNullOrWhiteSpace(to))
        {
            return false;
        }

        if (_deliverySafetyOptions.OfficialWhatsAppGroupIds.Any(id => string.Equals(id?.Trim(), to.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var configured = Environment.GetEnvironmentVariable("OFFICIAL_WHATSAPP_GROUP_ID");
        return !string.IsNullOrWhiteSpace(configured) &&
               string.Equals(configured.Trim(), to.Trim(), StringComparison.OrdinalIgnoreCase);
    }

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
