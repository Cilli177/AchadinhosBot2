using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using MassTransit;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class InstagramCommentReplyConsumer : IConsumer<ReplyInstagramCommentCommand>
{
    private readonly ISettingsStore _settingsStore;
    private readonly IMetaGraphClient _metaGraphClient;
    private readonly IInstagramCommentStore _commentStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly ILogger<InstagramCommentReplyConsumer> _logger;

    public InstagramCommentReplyConsumer(
        ISettingsStore settingsStore,
        IMetaGraphClient metaGraphClient,
        IInstagramCommentStore commentStore,
        IInstagramPublishLogStore publishLogStore,
        IIdempotencyStore idempotencyStore,
        IOptions<MessagingOptions> messagingOptions,
        ILogger<InstagramCommentReplyConsumer> logger)
    {
        _settingsStore = settingsStore;
        _metaGraphClient = metaGraphClient;
        _commentStore = commentStore;
        _publishLogStore = publishLogStore;
        _idempotencyStore = idempotencyStore;
        _messagingOptions = messagingOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<ReplyInstagramCommentCommand> context)
    {
        var command = context.Message;
        var ttl = TimeSpan.FromSeconds(Math.Max(30, _messagingOptions.OutboundDeduplicationWindowSeconds));
        if (!_idempotencyStore.TryBegin($"ig-comment-reply:{command.DeduplicationKey}", ttl))
        {
            _logger.LogInformation("Resposta de comentario Instagram duplicada ignorada. CommentId={CommentId}", command.CommentId);
            return;
        }

        var settings = await _settingsStore.GetAsync(context.CancellationToken);
        var publishSettings = settings.InstagramPublish ?? new Domain.Settings.InstagramPublishSettings();
        var result = await _metaGraphClient.ReplyToCommentAsync(publishSettings, command.CommentId, command.ReplyText, context.CancellationToken);

        var comment = string.IsNullOrWhiteSpace(command.CommentStoreId)
            ? null
            : await _commentStore.GetAsync(command.CommentStoreId, context.CancellationToken);
        if (comment is not null)
        {
            comment.Status = result.Success ? "approved" : "failed";
            comment.ApprovedReply = result.Success ? command.ReplyText : comment.ApprovedReply;
            await _commentStore.UpdateAsync(comment, context.CancellationToken);
        }

        await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "comment_reply",
            Success = result.Success,
            MediaId = command.MediaId,
            Error = result.Success ? null : result.Error,
            Details = $"CommentId={command.CommentId},Keyword={command.Keyword}"
        }, context.CancellationToken);

        if (!result.Success && result.IsTransient)
        {
            throw new InvalidOperationException(result.Error ?? "Falha transiente ao responder comentario do Instagram.");
        }
    }
}
