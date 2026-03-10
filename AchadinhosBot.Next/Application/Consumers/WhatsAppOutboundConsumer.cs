using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using MassTransit;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class WhatsAppOutboundConsumer : IConsumer<SendWhatsAppMessageCommand>
{
    private readonly IWhatsAppTransport _transport;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly ILogger<WhatsAppOutboundConsumer> _logger;

    public WhatsAppOutboundConsumer(
        IWhatsAppTransport transport,
        IIdempotencyStore idempotencyStore,
        IOptions<MessagingOptions> messagingOptions,
        ILogger<WhatsAppOutboundConsumer> logger)
    {
        _transport = transport;
        _idempotencyStore = idempotencyStore;
        _messagingOptions = messagingOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<SendWhatsAppMessageCommand> context)
    {
        var command = context.Message;
        var dedupeKey = $"wa-outbound:{command.DeduplicationKey}";
        var ttl = TimeSpan.FromSeconds(Math.Max(30, _messagingOptions.OutboundDeduplicationWindowSeconds));
        if (!_idempotencyStore.TryBegin(dedupeKey, ttl))
        {
            _logger.LogInformation("Mensagem outbound WhatsApp duplicada ignorada. Dedupe={DedupeKey}", command.DeduplicationKey);
            return;
        }

        WhatsAppSendResult result;
        switch (command.Kind)
        {
            case "image-url":
                result = await _transport.SendImageUrlAsync(
                    command.InstanceName,
                    command.To,
                    command.MediaUrl ?? string.Empty,
                    command.Text,
                    command.MimeType,
                    command.FileName,
                    context.CancellationToken);
                if (!result.Success && command.TextFallbackAllowed && !string.IsNullOrWhiteSpace(command.Text))
                {
                    result = await _transport.SendTextAsync(command.InstanceName, command.To, command.Text, context.CancellationToken);
                }
                break;

            case "image-bytes":
                var bytes = string.IsNullOrWhiteSpace(command.MediaBase64)
                    ? Array.Empty<byte>()
                    : Convert.FromBase64String(command.MediaBase64);
                result = await _transport.SendImageAsync(
                    command.InstanceName,
                    command.To,
                    bytes,
                    command.Text,
                    command.MimeType,
                    context.CancellationToken);
                if (!result.Success && command.TextFallbackAllowed && !string.IsNullOrWhiteSpace(command.Text))
                {
                    result = await _transport.SendTextAsync(command.InstanceName, command.To, command.Text, context.CancellationToken);
                }
                break;

            default:
                result = await _transport.SendTextAsync(
                    command.InstanceName,
                    command.To,
                    command.Text ?? string.Empty,
                    context.CancellationToken);
                break;
        }

        if (!result.Success)
        {
            throw new InvalidOperationException(result.Message ?? "Falha no envio outbound do WhatsApp.");
        }
    }
}
