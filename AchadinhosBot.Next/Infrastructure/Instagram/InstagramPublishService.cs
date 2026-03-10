using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Resilience;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramPublishService : IInstagramPublishService
{
    private readonly ISettingsStore _settingsStore;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMediaStore _mediaStore;
    private readonly IMetaGraphClient _metaGraphClient;
    private readonly IInstagramOutboundPublisher _publisher;
    private readonly IInstagramOutboundOutboxStore _outboxStore;
    private readonly string? _publicBaseUrl;
    private readonly ILogger<InstagramPublishService> _logger;

    public InstagramPublishService(
        ISettingsStore settingsStore,
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        IHttpClientFactory httpClientFactory,
        IMediaStore mediaStore,
        IMetaGraphClient metaGraphClient,
        IInstagramOutboundPublisher publisher,
        IInstagramOutboundOutboxStore outboxStore,
        IOptions<WebhookOptions> webhookOptions,
        ILogger<InstagramPublishService> logger)
    {
        _settingsStore = settingsStore;
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _httpClientFactory = httpClientFactory;
        _mediaStore = mediaStore;
        _metaGraphClient = metaGraphClient;
        _publisher = publisher;
        _outboxStore = outboxStore;
        _publicBaseUrl = webhookOptions.Value.PublicBaseUrl;
        _logger = logger;
    }

    public async Task<InstagramPublishDispatchResult> QueuePublishAsync(string draftId, string? actor, CancellationToken cancellationToken)
    {
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
        if (!publishSettings.Enabled)
        {
            return new InstagramPublishDispatchResult(false, "disabled", string.Empty, false, StatusCodes.Status400BadRequest, "Publicacao Instagram desativada.");
        }

        var draft = await _publishStore.GetAsync(draftId, cancellationToken);
        if (draft is null)
        {
            return new InstagramPublishDispatchResult(false, "missing-draft", string.Empty, false, StatusCodes.Status404NotFound, "Rascunho nao encontrado.");
        }

        var command = new PublishInstagramPostCommand
        {
            MessageId = Guid.NewGuid().ToString("N"),
            DraftId = draftId,
            RequestedBy = actor,
            DeduplicationKey = OutboundMessageFingerprint.Compute("instagram", "publish", draftId, draft.CreatedAt.ToString("O"))
        };

        try
        {
            await _publisher.PublishAsync(command, cancellationToken);
            await AppendLogAsync("publish_queued", true, draftId, null, null, $"Mode=rabbitmq,Actor={actor}", cancellationToken);
            return new InstagramPublishDispatchResult(true, "rabbitmq", command.MessageId, false, StatusCodes.Status202Accepted);
        }
        catch (Exception publishException)
        {
            _logger.LogWarning(publishException, "Falha ao publicar comando de Instagram {MessageId}. Persistindo em outbox local.", command.MessageId);
            try
            {
                await _outboxStore.SaveAsync(new InstagramOutboundEnvelope
                {
                    MessageId = command.MessageId,
                    MessageType = nameof(PublishInstagramPostCommand),
                    PayloadJson = JsonSerializer.Serialize(command)
                }, cancellationToken);
                await AppendLogAsync("publish_queued", true, draftId, null, null, $"Mode=local-outbox,Actor={actor}", cancellationToken);
                return new InstagramPublishDispatchResult(true, "local-outbox", command.MessageId, true, StatusCodes.Status202Accepted);
            }
            catch (Exception outboxException)
            {
                _logger.LogError(outboxException, "Falha ao persistir comando de Instagram {MessageId}.", command.MessageId);
                return new InstagramPublishDispatchResult(false, "failed", command.MessageId, false, StatusCodes.Status500InternalServerError, $"{publishException.Message} | {outboxException.Message}");
            }
        }
    }

    public async Task<InstagramPublishExecutionOutcome> ExecutePublishAsync(string draftId, CancellationToken cancellationToken)
    {
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
        var settingsError = ValidateSettings(publishSettings);
        if (settingsError is not null)
        {
            await AppendLogAsync("publish", false, draftId, null, settingsError, null, cancellationToken);
            return new InstagramPublishExecutionOutcome(false, StatusCodes.Status400BadRequest, null, settingsError, draftId);
        }

        var draft = await _publishStore.GetAsync(draftId, cancellationToken);
        if (draft is null)
        {
            await AppendLogAsync("publish", false, draftId, null, "Rascunho nao encontrado.", null, cancellationToken);
            return new InstagramPublishExecutionOutcome(false, StatusCodes.Status404NotFound, null, "Rascunho nao encontrado.", draftId);
        }

        var effectiveCaption = ResolveEffectiveCaption(draft);
        draft.PostType = InstagramWorkflowSupport.NormalizePostType(draft.PostType);
        draft.SelectedImageIndexes = InstagramWorkflowSupport.SanitizeSelectedIndexes(draft.SelectedImageIndexes, draft.ImageUrls.Count);

        var selectedImageUrls = InstagramWorkflowSupport.ResolveSelectedImageUrls(draft);
        var publishImageUrls = selectedImageUrls;
        var normalized = await InstagramWorkflowSupport.NormalizeInstagramImagesAsync(
            _httpClientFactory,
            _mediaStore,
            _publicBaseUrl,
            selectedImageUrls,
            cancellationToken);
        if (normalized.Count > 0)
        {
            publishImageUrls = normalized;
        }

        var validationError = ValidateDraft(draft, effectiveCaption, publishImageUrls);
        if (validationError is not null)
        {
            draft.Status = "failed";
            draft.MediaId = null;
            draft.Error = validationError;
            await _publishStore.UpdateAsync(draft, cancellationToken);
            await AppendLogAsync("publish", false, draft.Id, null, validationError, "quality=validation", cancellationToken);
            return new InstagramPublishExecutionOutcome(false, StatusCodes.Status400BadRequest, null, validationError, draft.Id);
        }

        var caption = InstagramWorkflowSupport.BuildCaption(effectiveCaption, draft.Hashtags, draft.Ctas);
        var publishResult = await _metaGraphClient.PublishAsync(publishSettings, draft.PostType, publishImageUrls, caption, cancellationToken);
        if (!publishResult.Success &&
            normalized.Count > 0 &&
            selectedImageUrls.Count > 0 &&
            InstagramWorkflowSupport.IsMediaTypeError(publishResult.Error))
        {
            var fallbackOriginals = selectedImageUrls.Where(x => !InstagramWorkflowSupport.IsLikelyWebpUrl(x)).ToList();
            if (fallbackOriginals.Count > 0)
            {
                publishResult = await _metaGraphClient.PublishAsync(publishSettings, draft.PostType, fallbackOriginals, caption, cancellationToken);
            }
        }

        draft.Status = publishResult.Success ? "published" : "failed";
        draft.MediaId = publishResult.MediaId;
        draft.Error = publishResult.Success ? null : publishResult.Error;
        await _publishStore.UpdateAsync(draft, cancellationToken);
        await AppendLogAsync(
            "publish",
            publishResult.Success,
            draft.Id,
            publishResult.MediaId,
            publishResult.Success ? null : publishResult.Error,
            publishResult.Success ? $"Publicado com sucesso (AutoReply={draft.AutoReplyEnabled})" : "Falha ao publicar",
            cancellationToken);

        return new InstagramPublishExecutionOutcome(
            publishResult.Success,
            publishResult.Success ? StatusCodes.Status200OK : StatusCodes.Status502BadGateway,
            publishResult.MediaId,
            publishResult.Error,
            draft.Id,
            publishResult.IsTransient);
    }

    private async Task AppendLogAsync(string action, bool success, string? draftId, string? mediaId, string? error, string? details, CancellationToken cancellationToken)
    {
        await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = action,
            Success = success,
            DraftId = draftId,
            MediaId = mediaId,
            Error = error,
            Details = details
        }, cancellationToken);
    }

    private static string ResolveEffectiveCaption(InstagramPublishDraft draft)
    {
        if (!string.IsNullOrWhiteSpace(draft.Caption))
        {
            return draft.Caption;
        }

        if (draft.CaptionOptions.Count == 0)
        {
            return string.Empty;
        }

        var idx = draft.SelectedCaptionIndex <= 0 ? 1 : draft.SelectedCaptionIndex;
        idx = Math.Min(idx, draft.CaptionOptions.Count);
        return draft.CaptionOptions[idx - 1];
    }

    private static string? ValidateSettings(InstagramPublishSettings settings)
    {
        if (!settings.Enabled)
        {
            return "Publicacao Instagram desativada.";
        }

        if (string.IsNullOrWhiteSpace(settings.AccessToken) || settings.AccessToken == "********")
        {
            return "Access token nao configurado.";
        }

        if (string.IsNullOrWhiteSpace(settings.InstagramUserId))
        {
            return "Instagram user id nao configurado.";
        }

        return null;
    }

    private static string? ValidateDraft(InstagramPublishDraft draft, string effectiveCaption, IReadOnlyList<string> publishImageUrls)
    {
        if (string.IsNullOrWhiteSpace(draft.ProductName))
        {
            return "Produto vazio no rascunho. Defina um produto real antes de publicar.";
        }

        if (publishImageUrls.Count == 0 || publishImageUrls.All(string.IsNullOrWhiteSpace))
        {
            return "Sem imagens para validar/publicar.";
        }

        if (string.IsNullOrWhiteSpace(effectiveCaption))
        {
            return "Legenda vazia para publicacao.";
        }

        return null;
    }
}
