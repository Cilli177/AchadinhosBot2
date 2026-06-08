using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using MassTransit;
using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class WhatsAppOutboundConsumer : IConsumer<SendWhatsAppMessageCommand>
{
    private readonly IWhatsAppTransport _transport;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly IWhatsAppOutboundLogStore _outboundLogStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly DeliverySafetyOptions _deliverySafetyOptions;
    private readonly ILogger<WhatsAppOutboundConsumer> _logger;

    public WhatsAppOutboundConsumer(
        IWhatsAppTransport transport,
        IIdempotencyStore idempotencyStore,
        IWhatsAppOutboundLogStore outboundLogStore,
        IOptions<MessagingOptions> messagingOptions,
        IOptions<DeliverySafetyOptions> deliverySafetyOptions,
        ILogger<WhatsAppOutboundConsumer> logger)
    {
        _transport = transport;
        _idempotencyStore = idempotencyStore;
        _outboundLogStore = outboundLogStore;
        _messagingOptions = messagingOptions.Value;
        _deliverySafetyOptions = deliverySafetyOptions.Value;
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

        var releaseDedupeOnFailure = true;
        try
        {
            var candidateInstances = BuildCandidateInstances(command.InstanceName);
            WhatsAppSendResult? result = null;
            string? usedInstanceName = command.InstanceName;

            foreach (var candidateInstance in candidateInstances)
            {
                result = await SendWithInstanceAsync(command, candidateInstance, context.CancellationToken);
                usedInstanceName = candidateInstance;

                if (result.Success)
                {
                    break;
                }

                if (!IsClosedInstanceError(result.Message))
                {
                    break;
                }

                _logger.LogWarning(
                    "Falha outbound na instancia {InstanceName} por estado fechado. Tentando failover. MessageId={MessageId} To={To}",
                    candidateInstance,
                    command.MessageId,
                    command.To);
            }

            if (result is null || !result.Success)
            {
                throw new InvalidOperationException(result?.Message ?? "Falha no envio outbound do WhatsApp.");
            }

            releaseDedupeOnFailure = false;

            try
            {
                await _outboundLogStore.AppendAsync(new WhatsAppOutboundLogEntry
                {
                    MessageId = command.MessageId,
                    CreatedAtUtc = command.CreatedAtUtc,
                    Kind = command.Kind,
                    InstanceName = usedInstanceName,
                    To = command.To,
                    Text = command.Text,
                    MediaUrl = command.MediaUrl,
                    MimeType = command.MimeType,
                    FileName = command.FileName
                }, context.CancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao registrar log outbound do WhatsApp apos envio concluido. MessageId={MessageId}", command.MessageId);
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

    internal async Task<WhatsAppSendResult> SendWithInstanceAsync(
        SendWhatsAppMessageCommand command,
        string? instanceName,
        CancellationToken cancellationToken)
    {
        switch (command.Kind)
        {
            case "image-url":
                if (IsOfficialDestination(command.To) && string.IsNullOrWhiteSpace(command.MediaUrl))
                {
                    _logger.LogWarning(
                        "Comando outbound WhatsApp imagem sem URL bloqueado para grupo oficial. MessageId={MessageId} To={To}",
                        command.MessageId,
                        command.To);
                    return new WhatsAppSendResult(false, "Grupo oficial exige imagem valida; envio sem foto bloqueado.");
                }

                var imageUrlResult = await _transport.SendImageUrlAsync(
                    instanceName,
                    command.To,
                    command.MediaUrl ?? string.Empty,
                    command.Text,
                    command.MimeType,
                    command.FileName,
                    cancellationToken);
                if (!imageUrlResult.Success && command.TextFallbackAllowed && !string.IsNullOrWhiteSpace(command.Text))
                {
                    return await _transport.SendTextAsync(instanceName, command.To, command.Text, cancellationToken);
                }

                return imageUrlResult;

            case "image-bytes":
                if (IsOfficialDestination(command.To) && string.IsNullOrWhiteSpace(command.MediaBase64))
                {
                    _logger.LogWarning(
                        "Comando outbound WhatsApp imagem sem bytes bloqueado para grupo oficial. MessageId={MessageId} To={To}",
                        command.MessageId,
                        command.To);
                    return new WhatsAppSendResult(false, "Grupo oficial exige imagem valida; envio sem foto bloqueado.");
                }

                var bytes = string.IsNullOrWhiteSpace(command.MediaBase64)
                    ? Array.Empty<byte>()
                    : Convert.FromBase64String(command.MediaBase64);
                var imageBytesResult = await _transport.SendImageAsync(
                    instanceName,
                    command.To,
                    bytes,
                    command.Text,
                    command.MimeType,
                    cancellationToken);
                if (!imageBytesResult.Success && command.TextFallbackAllowed && !string.IsNullOrWhiteSpace(command.Text))
                {
                    return await _transport.SendTextAsync(instanceName, command.To, command.Text, cancellationToken);
                }

                return imageBytesResult;

            default:
                if (IsOfficialDestination(command.To))
                {
                    _logger.LogWarning(
                        "Comando outbound WhatsApp texto bloqueado para grupo oficial. MessageId={MessageId} To={To}",
                        command.MessageId,
                        command.To);
                    return new WhatsAppSendResult(false, "Grupo oficial exige imagem; envio de texto bloqueado.");
                }

                return await _transport.SendTextAsync(
                    instanceName,
                    command.To,
                    command.Text ?? string.Empty,
                    cancellationToken);
        }
    }

    private bool IsOfficialDestination(string? to)
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

    private IReadOnlyList<string?> BuildCandidateInstances(string? originalInstanceName)
    {
        var result = new List<string?> { originalInstanceName };

        foreach (var configured in _messagingOptions.ResolveWhatsAppFailoverInstances())
        {
            if (result.Any(x => string.Equals(x, configured, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            result.Add(configured);
        }

        return result;
    }

    private static bool IsClosedInstanceError(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return false;
        }

        return Regex.IsMatch(message, @"\besta\s+(?:close|connecting)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
