using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Resilience;
using Microsoft.AspNetCore.Http;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramWebhookService : IInstagramWebhookService
{
    private readonly ISettingsStore _settingsStore;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramCommentStore _commentStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IInstagramOutboundPublisher _publisher;
    private readonly IInstagramOutboundOutboxStore _outboxStore;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly ILogger<InstagramWebhookService> _logger;

    public InstagramWebhookService(
        ISettingsStore settingsStore,
        IInstagramPublishStore publishStore,
        IInstagramCommentStore commentStore,
        IInstagramPublishLogStore publishLogStore,
        IInstagramOutboundPublisher publisher,
        IInstagramOutboundOutboxStore outboxStore,
        IIdempotencyStore idempotencyStore,
        ILogger<InstagramWebhookService> logger)
    {
        _settingsStore = settingsStore;
        _publishStore = publishStore;
        _commentStore = commentStore;
        _publishLogStore = publishLogStore;
        _publisher = publisher;
        _outboxStore = outboxStore;
        _idempotencyStore = idempotencyStore;
        _logger = logger;
    }

    public async Task<InstagramWebhookProcessResult> ProcessAsync(string body, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return new InstagramWebhookProcessResult(true, 0, 0);
        }

        var settings = await _settingsStore.GetAsync(cancellationToken);
        var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
        var commentsProcessed = 0;
        var directMessagesProcessed = 0;

        foreach (var comment in InstagramWorkflowSupport.ExtractComments(body))
        {
            if (!string.IsNullOrWhiteSpace(comment.CommentId) &&
                !_idempotencyStore.TryBegin($"ig-comment:{comment.CommentId}", TimeSpan.FromDays(7)))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(publishSettings.InstagramUserId) &&
                !string.IsNullOrWhiteSpace(comment.FromId) &&
                string.Equals(comment.FromId, publishSettings.InstagramUserId, StringComparison.OrdinalIgnoreCase))
            {
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "comment_ignored_self",
                    Success = true,
                    MediaId = comment.MediaId,
                    Details = $"CommentId={comment.CommentId}"
                }, cancellationToken);
                continue;
            }

            var draft = await InstagramWorkflowSupport.FindDraftByMediaIdAsync(_publishStore, comment.MediaId, cancellationToken);
            var cta = InstagramWorkflowSupport.ResolveCtaReply(draft, publishSettings, comment.Text);
            comment.SuggestedReply = cta.Reply;
            comment.MatchedKeyword = cta.Keyword;
            comment.MatchedLink = cta.Link;

            var autoReplyAllowed = publishSettings.AutoReplyEnabled &&
                                   !string.IsNullOrWhiteSpace(cta.Reply) &&
                                   (!publishSettings.AutoReplyOnlyOnKeywordMatch || cta.HasKeywordMatch);

            await _commentStore.AddAsync(comment, cancellationToken);
            if (autoReplyAllowed &&
                !string.IsNullOrWhiteSpace(publishSettings.AccessToken) &&
                publishSettings.AccessToken != "********")
            {
                var storedComment = await ResolveStoredCommentAsync(comment, cancellationToken);
                if (storedComment is not null)
                {
                    storedComment.Status = "processing";
                    await _commentStore.UpdateAsync(storedComment, cancellationToken);

                    await EnqueueAsync(new ReplyInstagramCommentCommand
                    {
                        MessageId = Guid.NewGuid().ToString("N"),
                        CommentStoreId = storedComment.Id,
                        CommentId = comment.CommentId,
                        MediaId = comment.MediaId,
                        ReplyText = cta.Reply,
                        Keyword = cta.Keyword,
                        DeduplicationKey = OutboundMessageFingerprint.Compute("instagram", "comment-reply", comment.CommentId, cta.Reply)
                    }, cancellationToken);

                    if (publishSettings.AutoDmEnabled && cta.HasKeywordMatch && !string.IsNullOrWhiteSpace(comment.FromId))
                    {
                        storedComment.DmStatus = "queued";
                        storedComment.DmError = null;
                        await _commentStore.UpdateAsync(storedComment, cancellationToken);
                        await EnqueueAsync(new SendInstagramDirectMessageCommand
                        {
                            MessageId = Guid.NewGuid().ToString("N"),
                            RecipientId = comment.FromId!,
                            MessageText = InstagramWorkflowSupport.BuildCommentDmMessage(draft, publishSettings, storedComment, cta),
                            CommentStoreId = storedComment.Id,
                            MediaId = comment.MediaId,
                            Keyword = cta.Keyword,
                            DeduplicationKey = OutboundMessageFingerprint.Compute("instagram", "dm", comment.FromId, cta.Link, cta.Keyword)
                        }, cancellationToken);
                    }
                }
            }

            await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "comment_received",
                Success = true,
                MediaId = comment.MediaId,
                Details = $"CommentId={comment.CommentId},AutoReply={autoReplyAllowed},AutoDm={publishSettings.AutoDmEnabled}"
            }, cancellationToken);
            commentsProcessed++;
        }

        foreach (var directMessage in InstagramWorkflowSupport.ExtractDirectMessages(body))
        {
            if (directMessage.IsEcho ||
                string.IsNullOrWhiteSpace(directMessage.FromId) ||
                (!string.IsNullOrWhiteSpace(publishSettings.InstagramUserId) &&
                 string.Equals(directMessage.FromId, publishSettings.InstagramUserId, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var dmKeySeed = !string.IsNullOrWhiteSpace(directMessage.MessageId)
                ? directMessage.MessageId!
                : $"{directMessage.FromId}:{directMessage.Text}";
            if (!_idempotencyStore.TryBegin($"ig-dm:{dmKeySeed}", TimeSpan.FromDays(7)))
            {
                continue;
            }

            var cta = await InstagramWorkflowSupport.ResolveDmKeywordReplyAsync(_publishStore, publishSettings, directMessage.Text, cancellationToken);
            var shouldReply = publishSettings.AutoDmEnabled &&
                              !string.IsNullOrWhiteSpace(cta.Reply) &&
                              (!publishSettings.AutoReplyOnlyOnKeywordMatch || cta.HasKeywordMatch);

            if (shouldReply &&
                !string.IsNullOrWhiteSpace(publishSettings.AccessToken) &&
                publishSettings.AccessToken != "********")
            {
                await EnqueueAsync(new SendInstagramDirectMessageCommand
                {
                    MessageId = Guid.NewGuid().ToString("N"),
                    RecipientId = directMessage.FromId,
                    MessageText = InstagramWorkflowSupport.BuildInboundDmMessage(publishSettings, cta, directMessage.Text),
                    Keyword = cta.Keyword,
                    DeduplicationKey = OutboundMessageFingerprint.Compute("instagram", "dm-inbound", directMessage.FromId, directMessage.Text, cta.Keyword)
                }, cancellationToken);
            }

            await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "dm_inbound_received",
                Success = true,
                Details = $"FromId={directMessage.FromId},HasKeyword={cta.HasKeywordMatch},AutoDm={publishSettings.AutoDmEnabled}"
            }, cancellationToken);
            directMessagesProcessed++;
        }

        return new InstagramWebhookProcessResult(true, commentsProcessed, directMessagesProcessed);
    }

    public string? ValidateChallenge(string mode, string token, string challenge)
    {
        if (!string.Equals(mode, "subscribe", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var settings = _settingsStore.GetAsync(CancellationToken.None).GetAwaiter().GetResult();
        var verifyToken = settings.InstagramPublish?.VerifyToken;
        return !string.IsNullOrWhiteSpace(verifyToken) && string.Equals(token, verifyToken, StringComparison.Ordinal)
            ? challenge
            : null;
    }

    public async Task<InstagramManualReplyResult> QueueManualCommentReplyAsync(string commentStoreId, string reply, CancellationToken cancellationToken)
    {
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
        if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
        {
            return new InstagramManualReplyResult(false, StatusCodes.Status400BadRequest, "Access token nao configurado.");
        }

        var comment = await _commentStore.GetAsync(commentStoreId, cancellationToken);
        if (comment is null)
        {
            return new InstagramManualReplyResult(false, StatusCodes.Status404NotFound, "Comentario nao encontrado.");
        }

        comment.Status = "processing";
        comment.ApprovedReply = reply;
        await _commentStore.UpdateAsync(comment, cancellationToken);

        await EnqueueAsync(new ReplyInstagramCommentCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            CommentStoreId = comment.Id,
            CommentId = comment.CommentId,
            MediaId = comment.MediaId,
            ReplyText = reply,
            Keyword = comment.MatchedKeyword,
            DeduplicationKey = OutboundMessageFingerprint.Compute("instagram", "comment-reply-manual", comment.CommentId, reply)
        }, cancellationToken);

        return new InstagramManualReplyResult(true, StatusCodes.Status202Accepted);
    }

    private async Task EnqueueAsync(ReplyInstagramCommentCommand command, CancellationToken cancellationToken)
    {
        try
        {
            await _publisher.PublishAsync(command, cancellationToken);
        }
        catch (Exception ex)
        {
            await PersistEnvelopeAsync(command.MessageId, nameof(ReplyInstagramCommentCommand), command, ex, cancellationToken);
        }
    }

    private async Task EnqueueAsync(SendInstagramDirectMessageCommand command, CancellationToken cancellationToken)
    {
        try
        {
            await _publisher.PublishAsync(command, cancellationToken);
        }
        catch (Exception ex)
        {
            await PersistEnvelopeAsync(command.MessageId, nameof(SendInstagramDirectMessageCommand), command, ex, cancellationToken);
        }
    }

    private async Task PersistEnvelopeAsync(string messageId, string messageType, object payload, Exception publishException, CancellationToken cancellationToken)
    {
        _logger.LogWarning(publishException, "Falha ao publicar comando do Instagram {MessageType}/{MessageId}. Persistindo em outbox local.", messageType, messageId);
        await _outboxStore.SaveAsync(new InstagramOutboundEnvelope
        {
            MessageId = messageId,
            MessageType = messageType,
            PayloadJson = JsonSerializer.Serialize(payload)
        }, cancellationToken);
    }

    private async Task<InstagramCommentPending?> ResolveStoredCommentAsync(InstagramCommentPending justAdded, CancellationToken cancellationToken)
    {
        var pending = await _commentStore.ListPendingAsync(cancellationToken);
        return pending.FirstOrDefault(x => x.CommentId == justAdded.CommentId) ?? justAdded;
    }
}
