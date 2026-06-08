using System.Security.Claims;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

public static class ChannelAgentAdminEndpoints
{
    public static void MapChannelAgentAdminEndpoints(this WebApplication app)
    {
        app.MapPost("/api/agents/channel-offers/deep-analyze", async (
            ChannelOfferDeepAnalysisRequest req,
            HttpContext context,
            IChannelOfferDeepAnalysisService deepAnalysisService,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!AdminAuthorizationHelper.IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            if (string.IsNullOrWhiteSpace(req.MessageId))
            {
                return Results.BadRequest(new { success = false, error = "messageId obrigatorio." });
            }

            try
            {
                var result = await deepAnalysisService.AnalyzeAsync(req, ct);
                return Results.Ok(new
                {
                    success = true,
                    result
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { success = false, error = ex.Message });
            }
        });

        app.MapGet("/api/admin/channel-offer-context", async (
            string messageId,
            string? sourceChannel,
            HttpContext context,
            IChannelOfferCandidateStore candidateStore,
            IWhatsAppOutboundLogStore whatsAppOutboundLogStore,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!AdminAuthorizationHelper.IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            if (string.IsNullOrWhiteSpace(messageId))
                return Results.BadRequest(new { success = false, error = "messageId obrigatorio." });

            var normalizedSourceChannel = string.Equals(sourceChannel, "telegram", StringComparison.OrdinalIgnoreCase)
                ? "telegram"
                : "whatsapp";

            var candidate = await candidateStore.GetAsync(normalizedSourceChannel, messageId, ct);
            var message = candidate is not null
                ? ToMessage(candidate)
                : await whatsAppOutboundLogStore.GetAsync(messageId, ct);

            if (candidate is null && message is null)
                return Results.NotFound(new { success = false, error = "Oferta do canal nao encontrada." });

            var effectiveText = !string.IsNullOrWhiteSpace(candidate?.EffectiveText)
                ? candidate!.EffectiveText
                : message?.Text ?? string.Empty;
            var originalText = candidate?.SourceText ?? message?.Text ?? string.Empty;
            var effectiveOfferUrl = FirstNonEmpty(candidate?.EffectiveOfferUrl, ExtractFirstUrl(effectiveText), ExtractFirstUrl(originalText));
            var originalOfferUrl = FirstNonEmpty(candidate?.OriginalOfferUrl, ExtractFirstUrl(originalText), effectiveOfferUrl);
            var mediaUrl = candidate?.MediaUrl ?? message?.MediaUrl;
            var mediaKind = candidate?.MediaKind ?? ResolveMediaKind(message);

            return Results.Ok(new
            {
                success = true,
                context = new
                {
                    messageId,
                    sourceChannel = normalizedSourceChannel,
                    productName = BuildDraftProductName(effectiveText, effectiveOfferUrl),
                    sourceText = originalText,
                    effectiveText,
                    offerUrl = effectiveOfferUrl,
                    originalOfferUrl,
                    mediaUrl,
                    mediaKind,
                    requiresLinkConversion = candidate?.RequiresLinkConversion ?? false,
                    linkConversionApplied = candidate?.LinkConversionApplied ?? false,
                    sourceGroupTitle = candidate?.ChatTitle ?? message?.To ?? string.Empty
                }
            });
        });

        app.MapPost("/api/admin/reschedule-draft", async (
            AdminRescheduleDraftRequest req,
            HttpContext context,
            IInstagramPublishStore draftStore,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!AdminAuthorizationHelper.IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = await draftStore.GetAsync(req.DraftId, ct);
            if (draft == null)
                return Results.NotFound(new { success = false, error = "Draft nao encontrado." });

            if (string.Equals(draft.Status, "published", StringComparison.OrdinalIgnoreCase))
                return Results.BadRequest(new { success = false, error = "Draft ja publicado nao pode ser reagendado." });

            draft.ScheduledFor = req.ScheduledFor;
            draft.Status = req.ScheduledFor.HasValue ? "scheduled" : "draft";
            draft.Error = null;
            await draftStore.UpdateAsync(draft, ct);

            return Results.Ok(new
            {
                success = true,
                draftId = draft.Id,
                status = draft.Status,
                scheduledFor = draft.ScheduledFor
            });
        });

        app.MapPost("/api/admin/apply-channel-offer-recommendation", async (
            AdminApplyChannelOfferRecommendationRequest req,
            HttpContext context,
            IInstagramPublishStore draftStore,
            IWhatsAppOutboundLogStore whatsAppOutboundLogStore,
            IChannelOfferCandidateStore candidateStore,
            IMessageProcessor processor,
            ICatalogOfferStore catalogStore,
            IInstagramPostComposer composer,
            ISettingsStore settingsStore,
            IWhatsAppAgentMemoryStore memoryStore,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!AdminAuthorizationHelper.IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var action = (req.RecommendedAction ?? string.Empty).Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(action))
            {
                return Results.BadRequest(new { success = false, error = "recommendedAction obrigatoria." });
            }

            var sourceChannel = string.Equals(req.SourceChannel, "telegram", StringComparison.OrdinalIgnoreCase)
                ? "telegram"
                : "whatsapp";
            var candidate = await candidateStore.GetAsync(sourceChannel, req.MessageId, ct);
            var message = candidate is not null ? ToMessage(candidate) : await whatsAppOutboundLogStore.GetAsync(req.MessageId, ct);

            if (action == WhatsAppOfferScoutActions.ConvertLink)
            {
                return await ApplyLinkConversionAsync(req, candidate, processor, candidateStore, memoryStore, ct);
            }

            if (message is null)
            {
                return Results.NotFound(new { success = false, error = "Mensagem da oferta nao encontrada." });
            }

            if (candidate is not null && candidate.RequiresLinkConversion)
            {
                return Results.BadRequest(new { success = false, error = "Esta oferta exige conversao de link antes de qualquer outra acao." });
            }

            if (action == WhatsAppOfferScoutActions.CreateInstagramDraft)
            {
                return await CreateDraftAsync(req, context, draftStore, composer, settingsStore, memoryStore, message, ct);
            }

            if (string.IsNullOrWhiteSpace(req.ExistingDraftId))
            {
                return Results.BadRequest(new { success = false, error = "existingDraftId obrigatorio para esta acao." });
            }

            var existingDraft = await draftStore.GetAsync(req.ExistingDraftId, ct);
            if (existingDraft == null)
            {
                return Results.NotFound(new { success = false, error = "Draft correspondente nao encontrado." });
            }

            if (action == WhatsAppOfferScoutActions.AddToCatalog)
            {
                return await AddToCatalogAsync(req, context, draftStore, catalogStore, existingDraft, ct);
            }

            if (action == WhatsAppOfferScoutActions.ReviewAndPublish)
            {
                return await ReviewAndPublishAsync(req, context, draftStore, catalogStore, existingDraft, ct);
            }

            return Results.Ok(new { success = true, action, draftId = existingDraft.Id, noop = true });
        });
    }

    private static async Task<IResult> ApplyLinkConversionAsync(
        AdminApplyChannelOfferRecommendationRequest req,
        ChannelOfferCandidate? candidate,
        IMessageProcessor processor,
        IChannelOfferCandidateStore candidateStore,
        IWhatsAppAgentMemoryStore memoryStore,
        CancellationToken ct)
    {
        if (candidate is null)
            return Results.NotFound(new { success = false, error = "Candidato do canal nao encontrado." });

        if (!candidate.RequiresLinkConversion)
        {
            return Results.Ok(new { success = true, action = WhatsAppOfferScoutActions.ConvertLink, alreadyConverted = true, offerUrl = candidate.EffectiveOfferUrl });
        }

        var conversion = await processor.ProcessAsync(candidate.SourceText, "agent_apply_conversion", ct, originChatRef: candidate.ChatTitle);
        if (!TryGetStrictConvertedText(candidate.SourceText, conversion.Success, conversion.ConvertedLinks, conversion.ConvertedText, out var strictText))
        {
            return Results.BadRequest(new { success = false, error = "Nao foi possivel converter o link desta oferta com seguranca." });
        }

        candidate.EffectiveText = strictText;
        candidate.EffectiveOfferUrl = ExtractFirstUrl(strictText);
        candidate.RequiresLinkConversion = false;
        candidate.LinkConversionApplied = true;
        candidate.ConversionNote = "Link convertido manualmente pelo operador.";
        await candidateStore.UpsertManyAsync(new[] { candidate }, ct);
        await memoryStore.AppendAsync(new WhatsAppAgentMemoryEntry
        {
            MessageId = req.MessageId,
            EventType = "applied",
            RecommendedAction = WhatsAppOfferScoutActions.ConvertLink,
            AppliedAction = WhatsAppOfferScoutActions.ConvertLink,
            OperatorFeedback = "accepted",
            Outcome = "link_converted"
        }, ct);

        return Results.Ok(new { success = true, action = WhatsAppOfferScoutActions.ConvertLink, converted = true, offerUrl = candidate.EffectiveOfferUrl });
    }

    private static async Task<IResult> CreateDraftAsync(
        AdminApplyChannelOfferRecommendationRequest req,
        HttpContext context,
        IInstagramPublishStore draftStore,
        IInstagramPostComposer composer,
        ISettingsStore settingsStore,
        IWhatsAppAgentMemoryStore memoryStore,
        Domain.Logs.WhatsAppOutboundLogEntry message,
        CancellationToken ct)
    {
        var offerUrl = ExtractFirstUrl(message.Text);
        var sourceCaption = (message.Text ?? string.Empty).Trim();
        var productName = BuildDraftProductName(sourceCaption, offerUrl);
        var caption = sourceCaption;
        if (req.UseAiCaption)
        {
            var settings = await settingsStore.GetAsync(ct);
            var aiCaption = await composer.BuildAsync(productName, sourceCaption, settings.InstagramPosts, ct);
            if (!string.IsNullOrWhiteSpace(aiCaption))
            {
                caption = aiCaption.Trim();
            }
        }

        var suggestedKeyword = WhatsAppOfferScoutAgentService.BuildSuggestedKeyword(productName, sourceCaption, offerUrl ?? string.Empty);
        var suggestedPostType = NormalizeSuggestedPostType(req.SuggestedPostType, message);
        var draft = BuildDraftFromMessage(message, productName, caption, offerUrl, suggestedKeyword, suggestedPostType);
        ApplyCatalogIntent(context, draft, req.SendToCatalog, req.CatalogTarget);
        await draftStore.SaveAsync(draft, ct);
        await memoryStore.AppendAsync(new WhatsAppAgentMemoryEntry
        {
            MessageId = req.MessageId,
            EventType = "applied",
            RecommendedAction = WhatsAppOfferScoutActions.CreateInstagramDraft,
            AppliedAction = WhatsAppOfferScoutActions.CreateInstagramDraft,
            SuggestedPostType = suggestedPostType,
            MediaKind = WhatsAppOfferScoutAgentService.InferMediaKind(message),
            ExistingDraftId = req.ExistingDraftId,
            DraftId = draft.Id,
            OperatorFeedback = "accepted",
            Outcome = "draft_created"
        }, ct);

        return Results.Ok(new { success = true, action = WhatsAppOfferScoutActions.CreateInstagramDraft, draftId = draft.Id, status = draft.Status, postType = draft.PostType, catalogTarget = draft.CatalogTarget });
    }

    private static async Task<IResult> AddToCatalogAsync(
        AdminApplyChannelOfferRecommendationRequest req,
        HttpContext context,
        IInstagramPublishStore draftStore,
        ICatalogOfferStore catalogStore,
        InstagramPublishDraft existingDraft,
        CancellationToken ct)
    {
        var previousCatalogTarget = existingDraft.CatalogTarget;
        var previousSendToCatalog = existingDraft.SendToCatalog;
        ApplyCatalogIntent(context, existingDraft, true, req.CatalogTarget);
        if (!string.Equals(previousCatalogTarget, existingDraft.CatalogTarget, StringComparison.OrdinalIgnoreCase) ||
            previousSendToCatalog != existingDraft.SendToCatalog)
        {
            await draftStore.UpdateAsync(existingDraft, ct);
        }

        if (!string.Equals(existingDraft.Status, "published", StringComparison.OrdinalIgnoreCase))
        {
            return Results.Ok(new { success = true, action = WhatsAppOfferScoutActions.AddToCatalog, draftId = existingDraft.Id, scheduled = true, target = CatalogTargets.ResolveDraftTarget(existingDraft) });
        }

        var syncResult = await catalogStore.SyncFromPublishedDraftsAsync(new[] { existingDraft }, ct);
        return Results.Ok(new { success = true, action = WhatsAppOfferScoutActions.AddToCatalog, draftId = existingDraft.Id, target = CatalogTargets.ResolveDraftTarget(existingDraft), itemsUpdated = syncResult.Created + syncResult.Updated });
    }

    private static async Task<IResult> ReviewAndPublishAsync(
        AdminApplyChannelOfferRecommendationRequest req,
        HttpContext context,
        IInstagramPublishStore draftStore,
        ICatalogOfferStore catalogStore,
        InstagramPublishDraft existingDraft,
        CancellationToken ct)
    {
        existingDraft.Status = "published";
        existingDraft.Error = null;
        existingDraft.ScheduledFor = null;
        if (req.SendToCatalog || !string.IsNullOrWhiteSpace(req.CatalogTarget))
        {
            ApplyCatalogIntent(context, existingDraft, req.SendToCatalog, req.CatalogTarget);
        }

        await draftStore.UpdateAsync(existingDraft, ct);
        object? catalog = null;
        if (existingDraft.SendToCatalog || !string.Equals(CatalogTargets.ResolveDraftTarget(existingDraft), CatalogTargets.None, StringComparison.OrdinalIgnoreCase))
        {
            var syncResult = await catalogStore.SyncFromPublishedDraftsAsync(new[] { existingDraft }, ct);
            catalog = new { target = CatalogTargets.ResolveDraftTarget(existingDraft), itemsUpdated = syncResult.Created + syncResult.Updated };
        }

        return Results.Ok(new { success = true, action = WhatsAppOfferScoutActions.ReviewAndPublish, draftId = existingDraft.Id, status = existingDraft.Status, catalog });
    }

    private static Domain.Logs.WhatsAppOutboundLogEntry ToMessage(ChannelOfferCandidate candidate)
    {
        return new Domain.Logs.WhatsAppOutboundLogEntry
        {
            MessageId = candidate.MessageId,
            CreatedAtUtc = candidate.CreatedAtUtc,
            Kind = candidate.MediaKind,
            InstanceName = candidate.SourceChannel,
            To = candidate.ChatId,
            Text = string.IsNullOrWhiteSpace(candidate.EffectiveText) ? candidate.SourceText : candidate.EffectiveText,
            MediaUrl = candidate.MediaUrl,
            MimeType = candidate.MediaKind == "image" ? "image/agent" : candidate.MediaKind == "video" ? "video/agent" : null
        };
    }

    private static string ResolveMediaKind(Domain.Logs.WhatsAppOutboundLogEntry? message)
    {
        if (message is null)
            return "text";

        if (!string.IsNullOrWhiteSpace(message.Kind))
            return message.Kind;

        if (!string.IsNullOrWhiteSpace(message.MimeType))
        {
            if (message.MimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                return "image";

            if (message.MimeType.StartsWith("video/", StringComparison.OrdinalIgnoreCase))
                return "video";
        }

        return string.IsNullOrWhiteSpace(message.MediaUrl) ? "text" : "image";
    }

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();


    private static void ApplyCatalogIntent(HttpContext context, InstagramPublishDraft draft, bool sendToCatalog, string? catalogTarget)
    {
        var resolved = CatalogTargets.ResolveConfiguredTarget(catalogTarget, sendToCatalog, CatalogTargets.Prod);
        if (IsDevHost(context.Request.Host.Host) && string.Equals(resolved, CatalogTargets.Prod, StringComparison.OrdinalIgnoreCase))
        {
            resolved = CatalogTargets.Dev;
        }

        draft.CatalogTarget = resolved;
        draft.SendToCatalog = CatalogTargets.IsEnabled(resolved);
        draft.CatalogIntentLocked = true;
    }

    private static bool IsDevHost(string? host)
    {
        var value = host ?? string.Empty;
        return value.Contains("-dev.", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("achadinhos-dev", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase);
    }

    private static InstagramPublishDraft BuildDraftFromMessage(
        Domain.Logs.WhatsAppOutboundLogEntry message,
        string productName,
        string caption,
        string? offerUrl,
        string suggestedKeyword,
        string suggestedPostType)
    {
        var normalizedPostType = NormalizeSuggestedPostType(suggestedPostType, message);
        var mediaUrl = string.IsNullOrWhiteSpace(message.MediaUrl) ? null : message.MediaUrl.Trim();
        var isReel = string.Equals(normalizedPostType, WhatsAppOfferScoutPostTypes.Reel, StringComparison.OrdinalIgnoreCase);

        return new InstagramPublishDraft
        {
            ProductName = productName,
            PostType = isReel ? "reel" : "feed",
            Caption = caption,
            OfferUrl = offerUrl,
            VideoUrl = isReel ? mediaUrl : null,
            ImageUrls = !isReel && !string.IsNullOrWhiteSpace(mediaUrl) ? new List<string> { mediaUrl } : new List<string>(),
            Ctas = string.IsNullOrWhiteSpace(offerUrl)
                ? new List<InstagramCtaOption>()
                : new List<InstagramCtaOption> { new() { Keyword = suggestedKeyword, Link = offerUrl } },
            AutoReplyEnabled = !string.IsNullOrWhiteSpace(offerUrl),
            AutoReplyKeyword = string.IsNullOrWhiteSpace(offerUrl) ? null : suggestedKeyword,
            AutoReplyLink = offerUrl,
            Status = "draft"
        };
    }

    private static string NormalizeSuggestedPostType(string? suggestedPostType, Domain.Logs.WhatsAppOutboundLogEntry message)
    {
        var normalized = (suggestedPostType ?? string.Empty).Trim().ToLowerInvariant();
        if (normalized is WhatsAppOfferScoutPostTypes.Reel or WhatsAppOfferScoutPostTypes.Feed)
        {
            return normalized;
        }

        return WhatsAppOfferScoutAgentService.InferSuggestedPostType(message);
    }

    private static string BuildDraftProductName(string? caption, string? offerUrl)
    {
        var firstLine = Regex.Split(caption ?? string.Empty, @"\r?\n", RegexOptions.CultureInvariant)
            .Select(x => x.Trim())
            .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith("http", StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(firstLine))
        {
            return firstLine.Length > 120 ? firstLine[..120] : firstLine;
        }

        if (Uri.TryCreate(offerUrl, UriKind.Absolute, out var uri))
        {
            return uri.Host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        return "Oferta do canal";
    }

    private static string? ExtractFirstUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = Regex.Match(text, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Value.Trim().TrimEnd('.', ',', ';', ')', ']') : null;
    }

    private static bool TryGetStrictConvertedText(string originalText, bool conversionSuccess, int convertedLinks, string? convertedText, out string strictText)
    {
        strictText = string.Empty;
        if (!conversionSuccess || convertedLinks <= 0 || string.IsNullOrWhiteSpace(convertedText))
        {
            return false;
        }

        var originalUrls = ExtractNormalizedUrls(originalText);
        var convertedUrls = ExtractNormalizedUrls(convertedText);
        if (originalUrls.Count == 0 || convertedUrls.Count == 0)
        {
            return false;
        }

        foreach (var originalUrl in originalUrls)
        {
            if (convertedUrls.Contains(originalUrl))
            {
                return false;
            }
        }

        strictText = convertedText.Trim();
        return true;
    }

    private static HashSet<string> ExtractNormalizedUrls(string? text)
    {
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Regex.Matches(text ?? string.Empty, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var normalized = match.Value.Trim().TrimEnd('.', ',', ';', ')', ']');
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                urls.Add(normalized);
            }
        }

        return urls;
    }
}

public sealed record AdminApplyChannelOfferRecommendationRequest(
    string MessageId,
    string RecommendedAction,
    string? SourceChannel = null,
    string? ExistingDraftId = null,
    bool UseAiCaption = false,
    bool SendToCatalog = false,
    string? CatalogTarget = null,
    string? SuggestedPostType = null);

public sealed record AdminRescheduleDraftRequest(
    string DraftId,
    DateTimeOffset? ScheduledFor);
