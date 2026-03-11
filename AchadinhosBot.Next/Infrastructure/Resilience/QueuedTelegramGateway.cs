using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class QueuedTelegramGateway : ITelegramGateway
{
    private readonly ITelegramTransport _transport;
    private readonly ITelegramOutboundPublisher _publisher;
    private readonly ITelegramOutboundOutboxStore _outboxStore;
    private readonly ILogger<QueuedTelegramGateway> _logger;

    public QueuedTelegramGateway(
        ITelegramTransport transport,
        ITelegramOutboundPublisher publisher,
        ITelegramOutboundOutboxStore outboxStore,
        ILogger<QueuedTelegramGateway> logger)
    {
        _transport = transport;
        _publisher = publisher;
        _outboxStore = outboxStore;
        _logger = logger;
    }

    public Task<TelegramConnectResult> ConnectAsync(string? botToken, CancellationToken cancellationToken)
        => _transport.ConnectAsync(botToken, cancellationToken);

    public Task<TelegramSendResult> SendTextAsync(string? botToken, long chatId, string text, CancellationToken cancellationToken)
        => QueueAsync(new SendTelegramMessageCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            DeduplicationKey = OutboundMessageFingerprint.Compute("telegram", "text", botToken, chatId.ToString(), text),
            BotToken = botToken,
            ChatId = chatId,
            Text = text,
            TextFallbackAllowed = false
        }, cancellationToken);

    public Task<TelegramSendResult> SendPhotoAsync(string? botToken, long chatId, string photoUrl, string? caption, CancellationToken cancellationToken)
        => QueueAsync(new SendTelegramMessageCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            DeduplicationKey = OutboundMessageFingerprint.Compute("telegram", "photo", botToken, chatId.ToString(), photoUrl, caption),
            BotToken = botToken,
            ChatId = chatId,
            Text = caption,
            ImageUrl = photoUrl,
            TextFallbackAllowed = !string.IsNullOrWhiteSpace(caption)
        }, cancellationToken);

    private async Task<TelegramSendResult> QueueAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken)
    {
        try
        {
            await _publisher.PublishAsync(command, cancellationToken);
            return new TelegramSendResult(true, "Mensagem Telegram enfileirada.");
        }
        catch (Exception publishException)
        {
            _logger.LogWarning(publishException, "Falha ao publicar outbound Telegram {MessageId}. Persistindo em outbox local.", command.MessageId);
            try
            {
                await _outboxStore.SaveAsync(command, cancellationToken);
                return new TelegramSendResult(true, "Mensagem persistida em outbox local do Telegram.");
            }
            catch (Exception outboxException)
            {
                _logger.LogError(outboxException, "Falha ao persistir outbound Telegram {MessageId}.", command.MessageId);
                return new TelegramSendResult(false, $"{publishException.Message} | {outboxException.Message}");
            }
        }
    }
}
