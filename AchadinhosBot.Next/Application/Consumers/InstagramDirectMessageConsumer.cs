using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using MassTransit;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class InstagramDirectMessageConsumer : IConsumer<SendInstagramDirectMessageCommand>
{
    private readonly ISettingsStore _settingsStore;
    private readonly IMetaGraphClient _metaGraphClient;
    private readonly IInstagramCommentStore _commentStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly ILogger<InstagramDirectMessageConsumer> _logger;

    public InstagramDirectMessageConsumer(
        ISettingsStore settingsStore,
        IMetaGraphClient metaGraphClient,
        IInstagramCommentStore commentStore,
        IInstagramPublishLogStore publishLogStore,
        IIdempotencyStore idempotencyStore,
        IOptions<MessagingOptions> messagingOptions,
        ILogger<InstagramDirectMessageConsumer> logger)
    {
        _settingsStore = settingsStore;
        _metaGraphClient = metaGraphClient;
        _commentStore = commentStore;
        _publishLogStore = publishLogStore;
        _idempotencyStore = idempotencyStore;
        _messagingOptions = messagingOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<SendInstagramDirectMessageCommand> context)
    {
        var command = context.Message;
        var dedupeKey = $"ig-dm-out:{command.DeduplicationKey}";
        var ttl = TimeSpan.FromSeconds(Math.Max(30, _messagingOptions.OutboundDeduplicationWindowSeconds));
        if (!_idempotencyStore.TryBegin(dedupeKey, ttl))
        {
            _logger.LogInformation("DM outbound Instagram duplicada ignorada. RecipientId={RecipientId}", command.RecipientId);
            return;
        }

        var releaseDedupeOnFailure = true;
        try
        {
            var settings = await _settingsStore.GetAsync(context.CancellationToken);
            var publishSettings = settings.InstagramPublish ?? new Domain.Settings.InstagramPublishSettings();
            var result = await _metaGraphClient.SendDirectMessageAsync(publishSettings, command.RecipientId, command.MessageText, context.CancellationToken);

            if (!result.Success && !result.IsTransient)
            {
                releaseDedupeOnFailure = false;
            }

            if (result.Success)
            {
                releaseDedupeOnFailure = false;
            }

            if (!string.IsNullOrWhiteSpace(command.CommentStoreId))
            {
                var comment = await _commentStore.GetAsync(command.CommentStoreId, context.CancellationToken);
                if (comment is not null)
                {
                    comment.DmStatus = result.Success ? "sent" : "failed";
                    comment.DmError = result.Success ? null : result.Error;
                    await _commentStore.UpdateAsync(comment, context.CancellationToken);
                }
            }

            await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "comment_dm_auto",
                Success = result.Success,
                MediaId = command.MediaId,
                Error = result.Success ? null : result.Error,
                Details = $"RecipientId={command.RecipientId},Keyword={command.Keyword},Provider={command.Provider}"
            }, context.CancellationToken);

            if (!result.Success && result.IsTransient)
            {
                throw new InvalidOperationException(result.Error ?? "Falha transiente ao enviar DM do Instagram.");
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
