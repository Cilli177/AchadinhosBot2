using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
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
    private readonly IVideoProcessingService _videoProcessingService;
    private readonly IInstagramOutboundPublisher _publisher;
    private readonly IInstagramOutboundOutboxStore _outboxStore;
    private readonly ICatalogOfferStore _catalogOfferStore;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly string? _publicBaseUrl;
    private readonly ILogger<InstagramPublishService> _logger;

    public InstagramPublishService(
        ISettingsStore settingsStore,
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        IHttpClientFactory httpClientFactory,
        IMediaStore mediaStore,
        IMetaGraphClient metaGraphClient,
        IVideoProcessingService videoProcessingService,
        IInstagramOutboundPublisher publisher,
        IInstagramOutboundOutboxStore outboxStore,
        ICatalogOfferStore catalogOfferStore,
        IIdempotencyStore idempotencyStore,
        IOptions<WebhookOptions> webhookOptions,
        ILogger<InstagramPublishService> logger)
    {
        _settingsStore = settingsStore;
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _httpClientFactory = httpClientFactory;
        _mediaStore = mediaStore;
        _metaGraphClient = metaGraphClient;
        _videoProcessingService = videoProcessingService;
        _publisher = publisher;
        _outboxStore = outboxStore;
        _catalogOfferStore = catalogOfferStore;
        _idempotencyStore = idempotencyStore;
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
            await AppendLogAsync("publish_queued", true, draftId, null, null, $"Mode=rabbitmq,Actor={actor}", draft.ProcessName, cancellationToken);
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
                await AppendLogAsync("publish_queued", true, draftId, null, null, $"Mode=local-outbox,Actor={actor}", draft.ProcessName, cancellationToken);
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
        var normalizedDraftId = draftId.Trim();
        var dedupeKey = $"instagram:publish:{normalizedDraftId.ToLowerInvariant()}";
        if (!_idempotencyStore.TryBegin(dedupeKey, TimeSpan.FromHours(6)))
        {
            var existingDraft = await _publishStore.GetAsync(normalizedDraftId, cancellationToken);
            if (existingDraft is not null &&
                string.Equals(existingDraft.Status, "published", StringComparison.OrdinalIgnoreCase))
            {
                return new InstagramPublishExecutionOutcome(
                    true,
                    StatusCodes.Status200OK,
                    existingDraft.MediaId,
                    null,
                    existingDraft.Id,
                    false);
            }

            return new InstagramPublishExecutionOutcome(
                false,
                StatusCodes.Status409Conflict,
                null,
                "Publicacao ja em andamento para este draft.",
                normalizedDraftId,
                false);
        }

        var settings = await _settingsStore.GetAsync(cancellationToken);
        var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
        var settingsError = ValidateSettings(publishSettings);
        if (settingsError is not null)
        {
            await AppendLogAsync("publish", false, draftId, null, settingsError, null, null, cancellationToken);
            return new InstagramPublishExecutionOutcome(false, StatusCodes.Status400BadRequest, null, settingsError, draftId);
        }

        var draft = await _publishStore.GetAsync(normalizedDraftId, cancellationToken);
        if (draft is null)
        {
            await AppendLogAsync("publish", false, normalizedDraftId, null, "Rascunho nao encontrado.", null, null, cancellationToken);
            return new InstagramPublishExecutionOutcome(false, StatusCodes.Status404NotFound, null, "Rascunho nao encontrado.", normalizedDraftId);
        }

        var isReel = string.Equals(InstagramWorkflowSupport.NormalizePostType(draft.PostType), "reel", StringComparison.OrdinalIgnoreCase);
        if (isReel)
        {
            EnsureCatalogIntentForReel(draft, publishSettings);
        }

        var effectiveCatalogTarget = CatalogTargets.ResolveEffectiveTarget(draft, publishSettings);
        if (isReel && !CatalogTargets.IsEnabled(effectiveCatalogTarget))
        {
            effectiveCatalogTarget = CatalogTargets.Prod;
            draft.CatalogTarget = effectiveCatalogTarget;
            draft.SendToCatalog = true;
        }
        var effectiveCaption = ResolveEffectiveCaption(draft);
        if (CatalogTargets.IsEnabled(effectiveCatalogTarget))
        {
            effectiveCaption = InstagramWorkflowSupport.PrepareCatalogCaption(effectiveCaption);
        }
        draft.PostType = InstagramWorkflowSupport.NormalizePostType(draft.PostType);
        draft.SelectedImageIndexes = InstagramWorkflowSupport.SanitizeSelectedIndexes(draft.SelectedImageIndexes, draft.ImageUrls.Count);

        var selectedImageUrls = InstagramWorkflowSupport.ResolveSelectedImageUrls(draft);
        var publishImageUrls = selectedImageUrls;
        var normalized = await InstagramWorkflowSupport.NormalizeInstagramImagesAsync(
            _httpClientFactory,
            _mediaStore,
            _publicBaseUrl,
            draft.PostType,
            selectedImageUrls,
            cancellationToken);
        if (normalized.Count > 0)
        {
            publishImageUrls = normalized;
        }

        var publishMediaUrls = publishImageUrls;
        if (!string.IsNullOrWhiteSpace(draft.VideoUrl))
        {
            var videoResult = await _videoProcessingService.PrepareForInstagramPublicationAsync(draft, _publicBaseUrl, cancellationToken);
            if (!videoResult.Success || string.IsNullOrWhiteSpace(videoResult.VideoUrl))
            {
                var error = videoResult.Error ?? "Falha ao preparar video para publicacao.";
                draft.Status = "failed";
                draft.MediaId = null;
                draft.Error = error;
                await _publishStore.UpdateAsync(draft, cancellationToken);
                await AppendLogAsync("publish", false, draft.Id, null, error, "quality=video-processing", draft.ProcessName, cancellationToken);
                return new InstagramPublishExecutionOutcome(false, StatusCodes.Status400BadRequest, null, error, draft.Id);
            }

            draft.VideoUrl = videoResult.VideoUrl;
            if (!string.IsNullOrWhiteSpace(videoResult.CoverUrl))
            {
                draft.VideoCoverUrl = videoResult.CoverUrl;
            }

            if (draft.PostType is "reel" or "story" || publishImageUrls.Count == 0)
            {
                publishMediaUrls = new List<string> { videoResult.VideoUrl };
            }
        }

        var validationError = ValidateDraft(draft, effectiveCaption, publishMediaUrls);
        if (validationError is not null)
        {
            draft.Status = "failed";
            draft.MediaId = null;
            draft.Error = validationError;
            await _publishStore.UpdateAsync(draft, cancellationToken);
            await AppendLogAsync("publish", false, draft.Id, null, validationError, "quality=validation", draft.ProcessName, cancellationToken);
            return new InstagramPublishExecutionOutcome(false, StatusCodes.Status400BadRequest, null, validationError, draft.Id);
        }

        var caption = InstagramWorkflowSupport.BuildCaption(effectiveCaption, draft.Hashtags, draft.Ctas);
        var publishResult = await _metaGraphClient.PublishAsync(publishSettings, draft.PostType, publishMediaUrls, caption, cancellationToken);
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

        if (CatalogTargets.IsEnabled(effectiveCatalogTarget))
        {
            draft.CatalogTarget = effectiveCatalogTarget;
            draft.SendToCatalog = true;
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
            draft.ProcessName,
            cancellationToken);

        if (publishResult.Success && CatalogTargets.IsEnabled(effectiveCatalogTarget))
        {
            await TrySyncCatalogAsync(draft, cancellationToken);
        }

        return new InstagramPublishExecutionOutcome(
            publishResult.Success,
            publishResult.Success ? StatusCodes.Status200OK : StatusCodes.Status502BadGateway,
            publishResult.MediaId,
            publishResult.Error,
            draft.Id,
            publishResult.IsTransient);
    }

    private static void EnsureCatalogIntentForReel(InstagramPublishDraft draft, InstagramPublishSettings publishSettings)
    {
        if (!string.IsNullOrWhiteSpace(draft.OriginalOfferUrl))
        {
            draft.OriginalOfferUrl = draft.OriginalOfferUrl.Trim();
        }
        else if (!string.IsNullOrWhiteSpace(draft.OfferUrl))
        {
            draft.OriginalOfferUrl = draft.OfferUrl.Trim();
        }

        if (string.IsNullOrWhiteSpace(draft.CatalogTarget) || string.Equals(draft.CatalogTarget, CatalogTargets.None, StringComparison.OrdinalIgnoreCase))
        {
            draft.CatalogTarget = CatalogTargets.IsEnabled(publishSettings.CatalogTarget)
                ? CatalogTargets.Normalize(publishSettings.CatalogTarget, CatalogTargets.Prod)
                : CatalogTargets.Prod;
        }

        draft.SendToCatalog = true;
        draft.CatalogIntentLocked = true;
    }

    private async Task AppendLogAsync(string action, bool success, string? draftId, string? mediaId, string? error, string? details, string? processName, CancellationToken cancellationToken)
    {
        await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = action,
            Success = success,
            DraftId = draftId,
            MediaId = mediaId,
            Error = error,
            Details = details,
            ProcessName = processName
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

    private static string? ValidateDraft(InstagramPublishDraft draft, string effectiveCaption, IReadOnlyList<string> publishMediaUrls)
    {
        if (string.IsNullOrWhiteSpace(draft.ProductName))
        {
            return "Produto vazio no rascunho. Defina um produto real antes de publicar.";
        }

        if (publishMediaUrls.Count == 0 || publishMediaUrls.All(string.IsNullOrWhiteSpace))
        {
            return "Sem midia para validar/publicar.";
        }

        if (string.IsNullOrWhiteSpace(effectiveCaption))
        {
            return "Legenda vazia para publicacao.";
        }

        return null;
    }

    private async Task TrySyncCatalogAsync(InstagramPublishDraft draft, CancellationToken cancellationToken)
    {
        try
        {
            var result = await _catalogOfferStore.SyncFromPublishedDraftsAsync(new[] { draft }, cancellationToken);
            await AppendLogAsync(
                "catalog_sync_after_publish",
                true,
                draft.Id,
                draft.MediaId,
                null,
                $"Created={result.Created};Updated={result.Updated};Deactivated={result.Deactivated}",
                draft.ProcessName,
                cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao sincronizar draft {DraftId} no catalogo apos publicacao.", draft.Id);
            await AppendLogAsync(
                "catalog_sync_after_publish",
                false,
                draft.Id,
                draft.MediaId,
                ex.Message,
                "sync_failed",
                draft.ProcessName,
                cancellationToken);
        }
    }
}
