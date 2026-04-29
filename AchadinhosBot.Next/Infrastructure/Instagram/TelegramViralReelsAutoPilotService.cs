using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class TelegramViralReelsAutoPilotService
{
    private const string DraftCreatedAction = "viral_reel_draft_created";
    private const string DuplicateSkippedAction = "viral_reel_duplicate_skipped";
    private const string SkippedAction = "viral_reel_skipped";
    private const string ApprovalSentAction = "viral_reel_approval_sent";
    private const string ApprovalMissingAction = "viral_reel_approval_target_missing";
    private const string FailedAction = "viral_reel_draft_failed";

    private readonly ISettingsStore _settingsStore;
    private readonly ITelegramUserbotService _telegramUserbot;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IWhatsAppTransport _whatsAppTransport;
    private readonly EvolutionOptions _evolutionOptions;
    private readonly ILogger<TelegramViralReelsAutoPilotService> _logger;

    public TelegramViralReelsAutoPilotService(
        ISettingsStore settingsStore,
        ITelegramUserbotService telegramUserbot,
        IInstagramPublishLogStore publishLogStore,
        IWhatsAppTransport whatsAppTransport,
        IOptions<EvolutionOptions> evolutionOptions,
        ILogger<TelegramViralReelsAutoPilotService> logger)
    {
        _settingsStore = settingsStore;
        _telegramUserbot = telegramUserbot;
        _publishLogStore = publishLogStore;
        _whatsAppTransport = whatsAppTransport;
        _evolutionOptions = evolutionOptions.Value;
        _logger = logger;
    }

    public async Task<TelegramViralReelsAutoPilotRunResult> RunOnceAsync(CancellationToken cancellationToken)
    {
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var publish = settings.InstagramPublish ?? new InstagramPublishSettings();
        if (!publish.ViralReelsAutoPilotEnabled)
        {
            return TelegramViralReelsAutoPilotRunResult.Skipped("viral_reels_autopilot_disabled");
        }

        var sourceChatId = publish.ViralReelsSourceTelegramChatId > 0
            ? publish.ViralReelsSourceTelegramChatId
            : 2425105459;

        if (!_telegramUserbot.IsReady)
        {
            await AppendLogAsync(SkippedAction, false, null, $"Reason=userbot_not_ready;SourceChatId={sourceChatId}", cancellationToken);
            return TelegramViralReelsAutoPilotRunResult.Skipped("userbot_not_ready");
        }

        var lookbackHours = Math.Clamp(publish.ViralReelsLookbackHours, 1, 168);
        var repeatWindowHours = Math.Clamp(publish.ViralReelsRepeatWindowHours, 1, 720);
        var perChatLimit = 1000;
        var offers = await _telegramUserbot.ListRecentOffersAsync(
            new[] { sourceChatId },
            perChatLimit,
            cancellationToken,
            includeMedia: false);
        var cutoff = DateTimeOffset.UtcNow.AddHours(-lookbackHours);
        var eligibleOffers = TelegramReelDraftSelectionHelper.SelectEligibleOffers(offers, requireMediaUrl: false);
        var usedCandidates = await GetUsedCandidateIndexAsync(cancellationToken);
        var selected = SelectFirstUnusedCandidate(eligibleOffers.Where(x => x.CreatedAtUtc >= cutoff), usedCandidates)
            ?? SelectFirstUnusedCandidate(eligibleOffers, usedCandidates);

        if (selected is null)
        {
            var reason = eligibleOffers.Count == 0 ? "no_eligible_video_link" : "all_candidates_already_used";
            await AppendLogAsync(SkippedAction, true, null, $"Reason={reason};SourceChatId={sourceChatId};LookbackHours={lookbackHours};Candidates={eligibleOffers.Count}", cancellationToken);
            return TelegramViralReelsAutoPilotRunResult.Skipped(reason);
        }

        var sourceKey = BuildSourceKey(selected.ChatId, selected.MessageId);
        var originalOfferUrl = TelegramReelDraftSelectionHelper.ExtractFirstUrl(selected.Text);
        var skippedCandidates = eligibleOffers
            .Where(x => !string.Equals(BuildSourceKey(x.ChatId, x.MessageId), sourceKey, StringComparison.OrdinalIgnoreCase))
            .Count(x => IsUsedCandidate(x, usedCandidates));
        if (skippedCandidates > 0)
        {
            await AppendLogAsync(
                DuplicateSkippedAction,
                true,
                null,
                $"SelectedSourceKey={sourceKey};SkippedCandidates={skippedCandidates};Dedupe=SourceKey,OriginalOfferUrl;RepeatWindowHours={repeatWindowHours}",
                cancellationToken);
        }

        if (publish.ViralReelsAutoPublishEnabled)
        {
            _logger.LogWarning("Viral Reels auto publish is configured true, but this phase keeps publishing disabled.");
        }

        var draft = await _telegramUserbot.CreateLatestReelDraftAsync(
            new TelegramUserbotCreateReelDraftRequest(sourceChatId, selected.MessageId, perChatLimit),
            cancellationToken);

        if (!draft.Success || string.IsNullOrWhiteSpace(draft.DraftId))
        {
            await AppendLogAsync(
                FailedAction,
                false,
                draft.DraftId,
                $"SourceKey={sourceKey};Message={Sanitize(draft.Message)}",
                cancellationToken);
            return new TelegramViralReelsAutoPilotRunResult(false, "draft_creation_failed", sourceKey, draft.DraftId, false, null);
        }

        await AppendLogAsync(
            DraftCreatedAction,
            true,
            draft.DraftId,
            $"SourceKey={sourceKey};OriginalOfferUrl={Sanitize(originalOfferUrl)};ProductName={Sanitize(draft.ProductName)};OfferUrl={Sanitize(draft.OfferUrl)};MediaUrl={Sanitize(draft.MediaUrl)}",
            cancellationToken);

        var approvalSent = false;
        string? approvalTarget = null;
        if (publish.ViralReelsSendForApproval && string.Equals(publish.ViralReelsApprovalChannel, "whatsapp", StringComparison.OrdinalIgnoreCase))
        {
            var groupId = publish.ViralReelsApprovalWhatsAppGroupId?.Trim();
            if (string.IsNullOrWhiteSpace(groupId))
            {
                await AppendLogAsync(ApprovalMissingAction, true, draft.DraftId, $"SourceKey={sourceKey};Channel=whatsapp", cancellationToken);
            }
            else
            {
                var instanceName = FirstNotEmpty(publish.ViralReelsApprovalWhatsAppInstanceName, _evolutionOptions.InstanceName);
                var send = await SendApprovalPackageAsync(instanceName, groupId, draft, cancellationToken);
                approvalSent = send.Success;
                approvalTarget = groupId;
                await AppendLogAsync(
                    ApprovalSentAction,
                    send.Success,
                    draft.DraftId,
                    $"SourceKey={sourceKey};Target={groupId};Instance={Sanitize(instanceName)};Message={Sanitize(send.Message)}",
                    cancellationToken);
            }
        }

        return new TelegramViralReelsAutoPilotRunResult(true, "viral_reel_draft_created", sourceKey, draft.DraftId, approvalSent, approvalTarget);
    }

    private async Task<UsedViralReelCandidateIndex> GetUsedCandidateIndexAsync(CancellationToken ct)
    {
        var logs = await _publishLogStore.ListAsync(50000, ct);
        var sourceKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var offerUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var log in logs)
        {
            if (!log.Success || !string.Equals(log.Action, DraftCreatedAction, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            AddDetailValue(log.Details, "SourceKey", sourceKeys);
            AddNormalizedUrlDetailValue(log.Details, "OriginalOfferUrl", offerUrls);
            AddNormalizedUrlDetailValue(log.Details, "OfferUrl", offerUrls);
        }

        return new UsedViralReelCandidateIndex(sourceKeys, offerUrls);
    }

    private async Task AppendLogAsync(string action, bool success, string? draftId, string? details, CancellationToken ct)
    {
        await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = action,
            Success = success,
            DraftId = draftId,
            Details = details
        }, ct);
    }

    private async Task<ApprovalPackageSendResult> SendApprovalPackageAsync(
        string? instanceName,
        string groupId,
        TelegramUserbotReelDraftResult draft,
        CancellationToken ct)
    {
        var results = new List<WhatsAppSendResult>();

        if (!string.IsNullOrWhiteSpace(draft.MediaUrl))
        {
            results.Add(await _whatsAppTransport.SendImageUrlAsync(
                instanceName,
                groupId,
                draft.MediaUrl.Trim(),
                BuildReelVideoCaption(draft),
                "video/mp4",
                "reel.mp4",
                ct));
        }

        results.Add(await _whatsAppTransport.SendTextAsync(
            instanceName,
            groupId,
            BuildInstagramCaptionApprovalMessage(draft),
            ct));

        if (!string.IsNullOrWhiteSpace(draft.ProductImageUrl))
        {
            results.Add(await _whatsAppTransport.SendImageUrlAsync(
                instanceName,
                groupId,
                draft.ProductImageUrl.Trim(),
                BuildCompleteOfferApprovalMessage(draft, includeImageHint: false),
                "image/jpeg",
                "oferta.jpg",
                ct));
        }
        else
        {
            results.Add(await _whatsAppTransport.SendTextAsync(
                instanceName,
                groupId,
                BuildCompleteOfferApprovalMessage(draft, includeImageHint: true),
                ct));
        }

        var success = results.Count > 0 && results.All(x => x.Success);
        var message = string.Join(" | ", results.Select(x => x.Message).Where(x => !string.IsNullOrWhiteSpace(x)));
        return new ApprovalPackageSendResult(success, string.IsNullOrWhiteSpace(message) ? "approval_package_sent" : message);
    }

    private static string BuildReelVideoCaption(TelegramUserbotReelDraftResult draft)
    {
        var sb = new StringBuilder();
        sb.AppendLine("🎬 VÍDEO DO REEL");
        sb.AppendLine($"Draft ID: {draft.DraftId}");
        sb.AppendLine($"Produto: {draft.ProductName ?? "-"}");
        return sb.ToString().Trim();
    }

    private static string BuildInstagramCaptionApprovalMessage(TelegramUserbotReelDraftResult draft)
    {
        var sb = new StringBuilder();
        sb.AppendLine("📝 LEGENDA DO INSTAGRAM");
        sb.AppendLine($"Draft ID: {draft.DraftId}");
        if (!string.IsNullOrWhiteSpace(draft.EditorUrl))
        {
            sb.AppendLine($"Revisar: {draft.EditorUrl}");
        }

        sb.AppendLine();
        sb.AppendLine(string.IsNullOrWhiteSpace(draft.InstagramCaption)
            ? "(sem legenda gerada)"
            : draft.InstagramCaption.Trim());
        return sb.ToString().Trim();
    }

    private static string BuildCompleteOfferApprovalMessage(TelegramUserbotReelDraftResult draft, bool includeImageHint)
    {
        var sb = new StringBuilder();
        sb.AppendLine("🔥 POST COMPLETO DA OFERTA");
        if (includeImageHint)
        {
            sb.AppendLine("⚠️ Foto da oferta não encontrada; enviando preview em texto.");
        }

        sb.AppendLine($"🛍️ Produto: {draft.ProductName ?? "-"}");
        sb.AppendLine($"👉 Link: {draft.OfferUrl ?? "-"}");
        if (!string.IsNullOrWhiteSpace(draft.AutoReplyMessage))
        {
            sb.AppendLine();
            sb.AppendLine(draft.AutoReplyMessage.Trim());
        }

        sb.AppendLine();
        sb.AppendLine("✅ Comandos no WhatsApp:");
        sb.AppendLine("- sim: aprova, publica o Reel, envia a oferta no WhatsApp oficial e sincroniza o catalogo");
        sb.AppendLine("- não: reprova o draft");
        sb.AppendLine("- ajustar: gera uma nova versão de legenda com IA");
        return sb.ToString().Trim();
    }

    private static string BuildApprovalMessage(TelegramUserbotReelDraftResult draft)
    {
        var sb = new StringBuilder();
        sb.AppendLine("REEL VIRAL - APROVAÇÃO");
        sb.AppendLine($"Draft ID: {draft.DraftId}");
        sb.AppendLine($"Produto: {draft.ProductName ?? "-"}");
        sb.AppendLine($"Link: {draft.OfferUrl ?? "-"}");
        sb.AppendLine($"Mídia: {draft.MediaUrl ?? "-"}");
        if (!string.IsNullOrWhiteSpace(draft.EditorUrl))
        {
            sb.AppendLine($"Revisar: {draft.EditorUrl}");
        }

        if (!string.IsNullOrWhiteSpace(draft.PreviewMessage))
        {
            sb.AppendLine();
            sb.AppendLine(draft.PreviewMessage);
        }

        sb.AppendLine();
        sb.AppendLine("Comandos no WhatsApp:");
        sb.AppendLine("- sim: aprova o draft");
        sb.AppendLine("- não: reprova o draft");
        sb.AppendLine("- ajustar: gera uma nova versão de legenda com IA");
        sb.AppendLine();
        sb.AppendLine("Publicação automática no Instagram: desativada. Aprovar não publica automaticamente.");
        return sb.ToString().Trim();
    }

    private static string BuildSourceKey(long chatId, string? messageId)
        => $"{chatId}:{(messageId ?? string.Empty).Trim()}";

    private static TelegramUserbotOfferMessage? SelectFirstUnusedCandidate(
        IEnumerable<TelegramUserbotOfferMessage> candidates,
        UsedViralReelCandidateIndex usedCandidates)
        => candidates.FirstOrDefault(x => !IsUsedCandidate(x, usedCandidates));

    private static bool IsUsedCandidate(
        TelegramUserbotOfferMessage offer,
        UsedViralReelCandidateIndex usedCandidates)
    {
        var sourceKey = BuildSourceKey(offer.ChatId, offer.MessageId);
        if (usedCandidates.SourceKeys.Contains(sourceKey))
        {
            return true;
        }

        var originalUrl = TelegramReelDraftSelectionHelper.ExtractFirstUrl(offer.Text);
        var normalizedUrl = NormalizeUrlForDedupe(originalUrl);
        return !string.IsNullOrWhiteSpace(normalizedUrl) && usedCandidates.OfferUrls.Contains(normalizedUrl);
    }

    private static void AddDetailValue(string? details, string key, ISet<string> values)
    {
        var value = GetDetailValue(details, key);
        if (!string.IsNullOrWhiteSpace(value))
        {
            values.Add(value.Trim());
        }
    }

    private static void AddNormalizedUrlDetailValue(string? details, string key, ISet<string> values)
    {
        var normalized = NormalizeUrlForDedupe(GetDetailValue(details, key));
        if (!string.IsNullOrWhiteSpace(normalized))
        {
            values.Add(normalized);
        }
    }

    private static string? GetDetailValue(string? details, string key)
    {
        if (string.IsNullOrWhiteSpace(details))
        {
            return null;
        }

        var prefix = key + "=";
        return details
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(x => x.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))?[prefix.Length..];
    }

    private static string? NormalizeUrlForDedupe(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim().TrimEnd('.', ',', ';', ')', ']', '>');
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            var builder = new UriBuilder(uri)
            {
                Scheme = uri.Scheme.ToLowerInvariant(),
                Host = uri.Host.ToLowerInvariant(),
                Fragment = string.Empty
            };

            return builder.Uri.AbsoluteUri.TrimEnd('/');
        }

        return trimmed.ToLowerInvariant();
    }

    private static string? FirstNotEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();

    private static string Sanitize(string? value)
        => (value ?? string.Empty).Replace(';', ',').ReplaceLineEndings(" ").Trim();
}

public sealed record TelegramViralReelsAutoPilotRunResult(
    bool Success,
    string Message,
    string? SourceKey = null,
    string? DraftId = null,
    bool ApprovalSent = false,
    string? ApprovalTarget = null)
{
    public static TelegramViralReelsAutoPilotRunResult Skipped(string message, string? sourceKey = null)
        => new(true, message, sourceKey);
}

internal sealed record ApprovalPackageSendResult(bool Success, string? Message);

internal sealed record UsedViralReelCandidateIndex(
    ISet<string> SourceKeys,
    ISet<string> OfferUrls);
