using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using MassTransit;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class TelegramOutboundConsumer : IConsumer<SendTelegramMessageCommand>
{
    private readonly ITelegramTransport _transport;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly ITelegramOutboundLogStore _outboundLogStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly ILogger<TelegramOutboundConsumer> _logger;

    public TelegramOutboundConsumer(
        ITelegramTransport transport,
        IIdempotencyStore idempotencyStore,
        ITelegramOutboundLogStore outboundLogStore,
        IOptions<MessagingOptions> messagingOptions,
        ILogger<TelegramOutboundConsumer> logger)
    {
        _transport = transport;
        _idempotencyStore = idempotencyStore;
        _outboundLogStore = outboundLogStore;
        _messagingOptions = messagingOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<SendTelegramMessageCommand> context)
    {
        var command = context.Message;
        var dedupeKey = $"telegram-outbound:{command.DeduplicationKey}";
        var ttl = TimeSpan.FromSeconds(Math.Max(30, _messagingOptions.OutboundDeduplicationWindowSeconds));
        if (!_idempotencyStore.TryBegin(dedupeKey, ttl))
        {
            _logger.LogInformation("Mensagem outbound Telegram duplicada ignorada. Dedupe={DedupeKey}", command.DeduplicationKey);
            return;
        }

        var releaseDedupeOnFailure = true;
        try
        {
            TelegramSendResult result;
            if (!string.IsNullOrWhiteSpace(command.ImageUrl))
            {
                result = await _transport.SendPhotoAsync(
                    command.BotToken,
                    command.ChatId,
                    command.ImageUrl,
                    command.Text,
                    context.CancellationToken);

                if (!result.Success && command.TextFallbackAllowed && !string.IsNullOrWhiteSpace(command.Text))
                {
                    result = await _transport.SendTextAsync(command.BotToken, command.ChatId, command.Text, context.CancellationToken);
                }
            }
            else
            {
                result = await _transport.SendTextAsync(command.BotToken, command.ChatId, command.Text ?? string.Empty, context.CancellationToken);
            }

            if (!result.Success)
            {
                throw new InvalidOperationException(result.Message ?? "Falha no envio outbound do Telegram.");
            }

            releaseDedupeOnFailure = false;

            try
            {
                await _outboundLogStore.AppendAsync(new TelegramOutboundLogEntry
                {
                    MessageId = command.MessageId,
                    CreatedAtUtc = command.CreatedAtUtc,
                    ChatId = command.ChatId,
                    Text = command.Text,
                    ImageUrl = command.ImageUrl
                }, context.CancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao registrar log outbound do Telegram apos envio concluido. MessageId={MessageId}", command.MessageId);
            }
        }
        catch
        {
            if (releaseDedupeOnFailure)
            {
                _idempotencyStore.RemoveByPrefix(dedupeKey);
            }

            throw;
        }
    }
}
