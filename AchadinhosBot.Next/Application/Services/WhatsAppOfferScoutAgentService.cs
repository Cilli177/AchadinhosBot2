using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppOfferScoutAgentService : IWhatsAppOfferScoutAgentService
{
    private readonly IWhatsAppOutboundLogStore _whatsAppOutboundLogStore;
    private readonly ITelegramOutboundLogStore _telegramOutboundLogStore;
    private readonly IInstagramPublishStore _publishStore;
    private readonly ICatalogOfferStore _catalogOfferStore;
    private readonly IClickLogStore _clickLogStore;
    private readonly IWhatsAppAgentMemoryStore _memoryStore;
    private readonly IChannelMonitorSelectionStore _channelMonitorSelectionStore;
    private readonly IChannelOfferCandidateStore _candidateStore;
    private readonly ISettingsStore _settingsStore;
    private readonly ITelegramUserbotService _telegramUserbotService;
    private readonly IMessageProcessor _messageProcessor;
    private readonly IAffiliateLinkService _affiliateLinkService;
    private readonly IWhatsAppOfferReasoner _reasoner;
    private readonly OpenAiInstagramPostGenerator _openAiGenerator;
    private readonly GeminiInstagramPostGenerator _geminiGenerator;
    private readonly DeepSeekInstagramPostGenerator _deepSeekGenerator;
    private readonly NemotronInstagramPostGenerator _nemotronGenerator;
    private readonly QwenInstagramPostGenerator _qwenGenerator;
    private readonly VilaNvidiaGenerator _vilaGenerator;

    public WhatsAppOfferScoutAgentService(
        IWhatsAppOutboundLogStore whatsAppOutboundLogStore,
        ITelegramOutboundLogStore telegramOutboundLogStore,
        IInstagramPublishStore publishStore,
        ICatalogOfferStore catalogOfferStore,
        IClickLogStore clickLogStore,
        IWhatsAppAgentMemoryStore memoryStore,
        IChannelMonitorSelectionStore channelMonitorSelectionStore,
        IChannelOfferCandidateStore candidateStore,
        ISettingsStore settingsStore,
        ITelegramUserbotService telegramUserbotService,
        IMessageProcessor messageProcessor,
        IAffiliateLinkService affiliateLinkService,
        IWhatsAppOfferReasoner reasoner,
        OpenAiInstagramPostGenerator openAiGenerator,
        GeminiInstagramPostGenerator geminiGenerator,
        DeepSeekInstagramPostGenerator deepSeekGenerator,
        NemotronInstagramPostGenerator nemotronGenerator,
        QwenInstagramPostGenerator qwenGenerator,
        VilaNvidiaGenerator vilaGenerator)
    {
        _whatsAppOutboundLogStore = whatsAppOutboundLogStore;
        _telegramOutboundLogStore = telegramOutboundLogStore;
        _publishStore = publishStore;
        _catalogOfferStore = catalogOfferStore;
        _clickLogStore = clickLogStore;
        _memoryStore = memoryStore;
        _channelMonitorSelectionStore = channelMonitorSelectionStore;
        _candidateStore = candidateStore;
        _settingsStore = settingsStore;
        _telegramUserbotService = telegramUserbotService;
        _messageProcessor = messageProcessor;
        _affiliateLinkService = affiliateLinkService;
        _reasoner = reasoner;
        _openAiGenerator = openAiGenerator;
        _geminiGenerator = geminiGenerator;
        _deepSeekGenerator = deepSeekGenerator;
        _nemotronGenerator = nemotronGenerator;
        _qwenGenerator = qwenGenerator;
        _vilaGenerator = vilaGenerator;
    }

    public async Task<WhatsAppOfferScoutResult> AnalyzeAsync(WhatsAppOfferScoutRequest request, CancellationToken cancellationToken)
    {
        var hoursWindow = Math.Clamp(request.HoursWindow, 1, 24 * 30);
        var maxItems = Math.Clamp(request.MaxItems, 1, 50);
        var start = DateTimeOffset.UtcNow.AddHours(-hoursWindow);
        var targetChatIds = (request.TargetChatIds ?? new List<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var sourceChannel = NormalizeSourceChannel(request.SourceChannel);
        var targetSelectionMode = NormalizeTargetSelectionMode(request.TargetSelectionMode);
        var persistedSelections = await _channelMonitorSelectionStore.ListBySourceAsync(sourceChannel, cancellationToken);
        var selectionCutoffByChatId = persistedSelections
            .Where(x => targetChatIds.Count == 0 || targetChatIds.Contains(x.ChatId))
            .ToDictionary(x => x.ChatId, x => x.SelectedAtUtc, StringComparer.OrdinalIgnoreCase);
        var envelopes = await LoadCandidatesAsync(sourceChannel, targetChatIds, cancellationToken);
        envelopes = await PreserveCandidateStateAsync(envelopes, cancellationToken);
        await _candidateStore.UpsertManyAsync(envelopes.Select(x => x.Candidate), cancellationToken);
        var messages = envelopes.Select(x => x.Message).ToList();
        var warnings = BuildWarnings(sourceChannel, targetChatIds, targetSelectionMode, persistedSelections, messages);
        var scoped = messages
            .Where(x => x.CreatedAtUtc >= start)
            .Where(x => targetChatIds.Count == 0 || targetChatIds.Contains(x.To))
            .Where(x => ShouldIncludeBySelectionMode(x, targetSelectionMode, selectionCutoffByChatId))
            .Where(IsRelevantOfferMessage)
            .GroupBy(BuildDeduplicationKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.CreatedAtUtc).First())
            .ToList();

        var drafts = await _publishStore.ListAsync(cancellationToken);
        var catalogDev = await _catalogOfferStore.GetByDraftIdAsync(cancellationToken, CatalogTargets.Dev);
        var catalogProd = await _catalogOfferStore.GetByDraftIdAsync(cancellationToken, CatalogTargets.Prod);
        var clicks = await _clickLogStore.QueryAsync(null, null, 5000, cancellationToken);
        var memoryByMessageId = await _memoryStore.GetLatestByMessageIdsAsync(scoped.Select(x => x.MessageId), cancellationToken);
        var settings = request.IncludeAiReasoning || request.UseAiDecision
            ? await _settingsStore.GetAsync(cancellationToken)
            : null;

        var suggestions = new List<WhatsAppOfferSuggestion>();
        foreach (var message in scoped)
        {
            var candidate = envelopes
                .FirstOrDefault(x => string.Equals(x.Message.MessageId, message.MessageId, StringComparison.OrdinalIgnoreCase))
                ?.Candidate;
            var suggestion = BuildSuggestion(message, drafts, catalogDev, catalogProd, clicks, candidate);
            EnrichWithMemory(suggestion, memoryByMessageId.TryGetValue(message.MessageId, out var memory) ? memory : null);
            ApplyConversionGuardrails(suggestion);
            if (string.Equals(suggestion.RecommendedAction, WhatsAppOfferScoutActions.NoAction, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (request.UseAiDecision && settings is not null)
            {
                await TryApplyAiDecisionAsync(message, suggestion, settings, cancellationToken);
            }

            if (request.IncludeAiReasoning && settings is not null)
            {
                suggestion.AiReasoning ??= await GenerateAiReasoningAsync(message, suggestion, settings, cancellationToken);
            }

            suggestions.Add(suggestion);
        }

        suggestions = suggestions
            .OrderByDescending(x => x.Score)
            .ThenByDescending(x => x.RecentClicks)
            .Take(maxItems)
            .ToList();

        return new WhatsAppOfferScoutResult
        {
            EvaluatedMessages = scoped.Count,
            SuggestedActions = suggestions.Count,
            Suggestions = suggestions,
            Mode = request.UseAiDecision ? "hybrid_ai_guarded" : "suggestion_only",
            SourceChannel = sourceChannel,
            TargetSelectionMode = targetSelectionMode,
            SourceMessagesAvailable = messages.Count,
            PersistedTargetCount = persistedSelections.Count,
            SelectionAnchoredTargetCount = selectionCutoffByChatId.Count,
            Warnings = warnings,
            Summary = BuildSummary(hoursWindow, scoped.Count, suggestions, request.UseAiDecision, sourceChannel, targetSelectionMode, selectionCutoffByChatId.Count, targetChatIds.Count)
        };
    }

    private async Task TryApplyAiDecisionAsync(
        WhatsAppOutboundLogEntry message,
        WhatsAppOfferSuggestion suggestion,
        AutomationSettings settings,
        CancellationToken cancellationToken)
    {
        var aiDecision = await _reasoner.ReasonAsync(message, suggestion, settings, cancellationToken);
        if (aiDecision is null)
        {
            suggestion.DecisionSource = "heuristic_fallback";
            return;
        }

        if (!IsGuardrailValid(aiDecision, suggestion))
        {
            suggestion.DecisionSource = "heuristic_guardrail_fallback";
            suggestion.DecisionProvider = aiDecision.Provider;
            if (!string.IsNullOrWhiteSpace(aiDecision.Reasoning))
            {
                suggestion.AiReasoning = aiDecision.Reasoning;
            }
            return;
        }

        suggestion.RecommendedAction = aiDecision.RecommendedAction;
        suggestion.DecisionSource = "ai_guarded";
        suggestion.DecisionProvider = aiDecision.Provider;
        suggestion.InstagramScore = Math.Max(aiDecision.InstagramScore, 0);
        suggestion.CatalogScore = Math.Max(aiDecision.CatalogScore, 0);
        suggestion.Score = Math.Max(suggestion.Score, Math.Max(suggestion.InstagramScore, suggestion.CatalogScore));
        if (!string.IsNullOrWhiteSpace(aiDecision.SuggestedKeyword))
        {
            suggestion.SuggestedKeyword = aiDecision.SuggestedKeyword;
        }

        if (!string.IsNullOrWhiteSpace(aiDecision.Reasoning))
        {
            suggestion.AiReasoning = aiDecision.Reasoning;
        }

        if (aiDecision.Risks.Count > 0)
        {
            foreach (var risk in aiDecision.Risks.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                if (!suggestion.Risks.Contains(risk, StringComparer.OrdinalIgnoreCase))
                {
                    suggestion.Risks.Add(risk);
                }
            }
        }
    }

    private static bool IsRelevantOfferMessage(Domain.Logs.WhatsAppOutboundLogEntry entry)
    {
        var text = entry.Text ?? string.Empty;
        return !string.IsNullOrWhiteSpace(ExtractFirstUrl(text)) ||
               !string.IsNullOrWhiteSpace(entry.MediaUrl) ||
               LooksLikeOfferText(text);
    }

    private static bool IsTinyUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        return host == "tinyurl.com" || host.EndsWith(".tinyurl.com", StringComparison.OrdinalIgnoreCase);
    }

    private static string ReplaceFirstUrl(string text, string replacement)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        var regex = new Regex("https?://[^\\s)>\"]+", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        return regex.Replace(text, replacement, 1);
    }

    private static bool ShouldIncludeBySelectionMode(
        WhatsAppOutboundLogEntry entry,
        string targetSelectionMode,
        IReadOnlyDictionary<string, DateTimeOffset> selectionCutoffByChatId)
    {
        if (!string.Equals(targetSelectionMode, WhatsAppOfferScoutSelectionModes.SinceSelection, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return selectionCutoffByChatId.TryGetValue(entry.To ?? string.Empty, out var selectedAtUtc)
            && entry.CreatedAtUtc >= selectedAtUtc;
    }

    private static string BuildDeduplicationKey(Domain.Logs.WhatsAppOutboundLogEntry entry)
    {
        var offerUrl = ExtractFirstUrl(entry.Text) ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(offerUrl))
        {
            return offerUrl.Trim().ToLowerInvariant();
        }

        var text = NormalizeWhitespace(entry.Text);
        return $"{text}|{entry.MediaUrl}".Trim().ToLowerInvariant();
    }

    private async Task<List<ScoutMessageEnvelope>> LoadCandidatesAsync(string sourceChannel, IReadOnlySet<string> targetChatIds, CancellationToken cancellationToken)
    {
        if (!string.Equals(sourceChannel, "telegram", StringComparison.OrdinalIgnoreCase))
        {
            return (await _whatsAppOutboundLogStore.ListRecentAsync(500, cancellationToken))
                .Select(message => new ScoutMessageEnvelope(message, BuildCandidateFromMessage("whatsapp", message, message.To, message.To, true)))
                .ToList();
        }

        var telegramChatIds = targetChatIds
            .Select(TryParseTelegramChatId)
            .Where(x => x.HasValue)
            .Select(x => x!.Value)
            .ToArray();

        if (telegramChatIds.Length == 0)
        {
            return (await _telegramOutboundLogStore.ListRecentAsync(500, cancellationToken))
                .Select(MapTelegramMessage)
                .Select(message => new ScoutMessageEnvelope(message, BuildCandidateFromMessage("telegram", message, message.To, message.To, true)))
                .ToList();
        }

        var offers = await _telegramUserbotService.ListRecentOffersAsync(telegramChatIds, 40, cancellationToken);
        var result = new List<ScoutMessageEnvelope>(offers.Count);
        foreach (var offer in offers)
        {
            var sourceText = offer.Text ?? string.Empty;
            var originalOfferUrl = ExtractFirstUrl(sourceText);
            var isPrimaryGroup = IsPrimarySourceGroup(offer.ChatTitle);
            var effectiveText = sourceText;
            var effectiveOfferUrl = originalOfferUrl;
            var requiresLinkConversion = !isPrimaryGroup && !string.IsNullOrWhiteSpace(originalOfferUrl);
            var linkConversionApplied = isPrimaryGroup;
            string? conversionNote = requiresLinkConversion
                ? "Conversao obrigatoria pendente antes de qualquer acao."
                : null;

            if (requiresLinkConversion && IsTinyUrl(originalOfferUrl))
            {
                var autoConversion = await _affiliateLinkService.ConvertAsync(
                    originalOfferUrl!,
                    cancellationToken,
                    source: "agent_scout_tiny_auto_convert");

                if (autoConversion.Success && !string.IsNullOrWhiteSpace(autoConversion.ConvertedUrl))
                {
                    effectiveOfferUrl = autoConversion.ConvertedUrl;
                    requiresLinkConversion = false;
                    linkConversionApplied = true;
                    conversionNote = "TinyURL expandido e convertido automaticamente.";
                    if (!string.Equals(effectiveOfferUrl, originalOfferUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        effectiveText = ReplaceFirstUrl(sourceText, effectiveOfferUrl!);
                    }
                }
                else
                {
                    var conversionFailureReason = !string.IsNullOrWhiteSpace(autoConversion.ValidationError)
                        ? autoConversion.ValidationError
                        : autoConversion.Error;
                    conversionNote = string.IsNullOrWhiteSpace(conversionFailureReason)
                        ? "Conversao obrigatoria pendente antes de qualquer acao."
                        : $"Conversao automatica de tinyurl nao concluida: {conversionFailureReason}";
                }
            }

            var message = new WhatsAppOutboundLogEntry
            {
                MessageId = offer.MessageId,
                CreatedAtUtc = offer.CreatedAtUtc,
                Kind = offer.MediaKind,
                InstanceName = "telegram-userbot",
                To = offer.ChatId.ToString(),
                Text = effectiveText,
                MediaUrl = offer.MediaUrl,
                MimeType = offer.MediaKind == "image"
                    ? "image/telegram"
                    : offer.MediaKind == "video"
                        ? "video/telegram"
                        : null
            };

            result.Add(new ScoutMessageEnvelope(message, new ChannelOfferCandidate
            {
                SourceChannel = "telegram",
                MessageId = offer.MessageId,
                CreatedAtUtc = offer.CreatedAtUtc,
                ChatId = offer.ChatId.ToString(),
                ChatTitle = offer.ChatTitle,
                SourceText = sourceText,
                EffectiveText = effectiveText,
                MediaUrl = offer.MediaUrl,
                MediaKind = offer.MediaKind,
                OriginalOfferUrl = originalOfferUrl,
                EffectiveOfferUrl = effectiveOfferUrl,
                RequiresLinkConversion = requiresLinkConversion,
                LinkConversionApplied = linkConversionApplied,
                ConversionNote = conversionNote,
                IsPrimarySourceGroup = isPrimaryGroup
            }));
        }

        return result;
    }

    private async Task<List<ScoutMessageEnvelope>> PreserveCandidateStateAsync(
        List<ScoutMessageEnvelope> envelopes,
        CancellationToken cancellationToken)
    {
        if (envelopes.Count == 0)
        {
            return envelopes;
        }

        var merged = new List<ScoutMessageEnvelope>(envelopes.Count);
        foreach (var envelope in envelopes)
        {
            var stored = await _candidateStore.GetAsync(
                envelope.Candidate.SourceChannel,
                envelope.Candidate.MessageId,
                cancellationToken);

            if (stored is null)
            {
                merged.Add(envelope);
                continue;
            }

            merged.Add(new ScoutMessageEnvelope(
                BuildMessageFromCandidate(envelope.Message, MergeCandidate(stored, envelope.Candidate)),
                MergeCandidate(stored, envelope.Candidate)));
        }

        return merged;
    }

    private static ChannelOfferCandidate BuildCandidateFromMessage(string sourceChannel, WhatsAppOutboundLogEntry message, string chatId, string chatTitle, bool isPrimarySourceGroup)
    {
        var text = message.Text ?? string.Empty;
        var offerUrl = ExtractFirstUrl(text);
        return new ChannelOfferCandidate
        {
            SourceChannel = sourceChannel,
            MessageId = message.MessageId,
            CreatedAtUtc = message.CreatedAtUtc,
            ChatId = chatId,
            ChatTitle = chatTitle,
            SourceText = text,
            EffectiveText = text,
            MediaUrl = message.MediaUrl,
            MediaKind = InferMediaKind(message),
            OriginalOfferUrl = offerUrl,
            EffectiveOfferUrl = offerUrl,
            LinkConversionApplied = isPrimarySourceGroup,
            IsPrimarySourceGroup = isPrimarySourceGroup
        };
    }

    private static ChannelOfferCandidate MergeCandidate(ChannelOfferCandidate stored, ChannelOfferCandidate incoming)
    {
        var preserveConverted = stored.LinkConversionApplied && !stored.RequiresLinkConversion;
        if (!preserveConverted)
        {
            return incoming;
        }

        return new ChannelOfferCandidate
        {
            SourceChannel = incoming.SourceChannel,
            MessageId = incoming.MessageId,
            CreatedAtUtc = incoming.CreatedAtUtc,
            ChatId = incoming.ChatId,
            ChatTitle = incoming.ChatTitle,
            SourceText = string.IsNullOrWhiteSpace(incoming.SourceText) ? stored.SourceText : incoming.SourceText,
            EffectiveText = string.IsNullOrWhiteSpace(stored.EffectiveText) ? incoming.EffectiveText : stored.EffectiveText,
            MediaUrl = incoming.MediaUrl,
            MediaKind = incoming.MediaKind,
            OriginalOfferUrl = string.IsNullOrWhiteSpace(incoming.OriginalOfferUrl) ? stored.OriginalOfferUrl : incoming.OriginalOfferUrl,
            EffectiveOfferUrl = string.IsNullOrWhiteSpace(stored.EffectiveOfferUrl) ? incoming.EffectiveOfferUrl : stored.EffectiveOfferUrl,
            RequiresLinkConversion = false,
            LinkConversionApplied = true,
            ConversionNote = stored.ConversionNote,
            IsPrimarySourceGroup = incoming.IsPrimarySourceGroup
        };
    }

    private static WhatsAppOutboundLogEntry BuildMessageFromCandidate(WhatsAppOutboundLogEntry originalMessage, ChannelOfferCandidate candidate)
    {
        return new WhatsAppOutboundLogEntry
        {
            MessageId = originalMessage.MessageId,
            CreatedAtUtc = originalMessage.CreatedAtUtc,
            Kind = originalMessage.Kind,
            InstanceName = originalMessage.InstanceName,
            To = originalMessage.To,
            Text = string.IsNullOrWhiteSpace(candidate.EffectiveText) ? originalMessage.Text : candidate.EffectiveText,
            MediaUrl = originalMessage.MediaUrl,
            MimeType = originalMessage.MimeType
        };
    }

    private static WhatsAppOfferSuggestion BuildSuggestion(
        Domain.Logs.WhatsAppOutboundLogEntry message,
        IReadOnlyList<InstagramPublishDraft> drafts,
        IReadOnlyDictionary<string, CatalogOfferItem> catalogDev,
        IReadOnlyDictionary<string, CatalogOfferItem> catalogProd,
        IReadOnlyList<Domain.Logs.ClickLogEntry> clickLogs,
        ChannelOfferCandidate? candidate)
    {
        var resolvedText = string.IsNullOrWhiteSpace(candidate?.EffectiveText)
            ? (message.Text ?? string.Empty)
            : candidate!.EffectiveText;
        var offerUrl = string.IsNullOrWhiteSpace(candidate?.EffectiveOfferUrl)
            ? (ExtractFirstUrl(resolvedText) ?? string.Empty)
            : candidate!.EffectiveOfferUrl!;
        var caption = resolvedText.Trim();
        var imageUrl = !string.IsNullOrWhiteSpace(message.MediaUrl) ? message.MediaUrl!.Trim() : null;
        var mediaKind = InferMediaKind(message);
        var title = BuildProductName(caption, offerUrl);
        var suggestedKeyword = BuildSuggestedKeyword(title, caption, offerUrl);
        var suggestedPostType = InferSuggestedPostType(message, imageUrl);
        var matchingDraft = FindMatchingDraft(drafts, offerUrl, caption);
        var inCatalogDev = matchingDraft is not null && catalogDev.ContainsKey(matchingDraft.Id);
        var inCatalogProd = matchingDraft is not null && catalogProd.ContainsKey(matchingDraft.Id);
        var recentClicks = CountClicks(clickLogs, offerUrl, matchingDraft);

        var reasons = new List<string>();
        var risks = new List<string>();
        var score = 0;
        var instagramScore = 0;
        var catalogScore = 0;
        var action = WhatsAppOfferScoutActions.NoAction;

        if (!string.IsNullOrWhiteSpace(offerUrl))
        {
            score += 20;
            instagramScore += 12;
            catalogScore += 12;
            reasons.Add("Post do WhatsApp contem link de oferta aproveitavel.");
        }
        else
        {
            risks.Add("Post sem link detectado no texto.");
            score -= 20;
            instagramScore -= 10;
            catalogScore -= 12;
        }

        if (!string.IsNullOrWhiteSpace(imageUrl))
        {
            score += 12;
            instagramScore += 18;
            reasons.Add("Post ja possui imagem reaproveitavel para Instagram.");
        }
        else
        {
            risks.Add("Post sem imagem publica reaproveitavel.");
            score -= 8;
            instagramScore -= 10;
        }

        if (string.Equals(mediaKind, "video", StringComparison.OrdinalIgnoreCase))
        {
            instagramScore += 18;
            score += 10;
            reasons.Add("Midia em video favorece recomendacao de reel.");
        }
        else if (string.Equals(mediaKind, "text", StringComparison.OrdinalIgnoreCase))
        {
            instagramScore -= 8;
            catalogScore += 10;
            reasons.Add("Oferta sem midia tende a performar melhor como catalogo do que como post imediato.");
        }

        if (recentClicks > 0)
        {
            score += Math.Min(recentClicks * 4, 24);
            instagramScore += Math.Min(recentClicks * 2, 12);
            catalogScore += Math.Min(recentClicks * 3, 18);
            reasons.Add($"Oferta recebeu {recentClicks} clique(s) recentes.");
        }

        if (matchingDraft is null)
        {
            score += 18;
            instagramScore += 24;
            reasons.Add("Ainda nao existe draft correspondente no Instagram.");
            action = WhatsAppOfferScoutActions.CreateInstagramDraft;
        }
        else
        {
            reasons.Add($"Ja existe draft correspondente com status {matchingDraft.Status}.");
            if (string.Equals(matchingDraft.Status, "published", StringComparison.OrdinalIgnoreCase) && !inCatalogDev && !inCatalogProd)
            {
                score += 16;
                catalogScore += 24;
                reasons.Add("Draft ja publicado, mas ainda fora do catalogo.");
                action = WhatsAppOfferScoutActions.AddToCatalog;
            }
            else if (!string.Equals(matchingDraft.Status, "published", StringComparison.OrdinalIgnoreCase))
            {
                score += 10;
                instagramScore += 16;
                action = WhatsAppOfferScoutActions.ReviewAndPublish;
            }
            else
            {
                instagramScore += 6;
                catalogScore += 6;
                action = WhatsAppOfferScoutActions.Review;
            }
        }

        if (inCatalogDev || inCatalogProd)
        {
            reasons.Add("Oferta ja esta representada no catalogo.");
            score -= 10;
            catalogScore -= 18;
            if (action == WhatsAppOfferScoutActions.AddToCatalog)
            {
                action = WhatsAppOfferScoutActions.Review;
            }
        }

        if (string.IsNullOrWhiteSpace(caption))
        {
            risks.Add("Post sem texto reaproveitavel para legenda.");
            score -= 6;
            instagramScore -= 8;
        }

        if (!string.IsNullOrWhiteSpace(suggestedKeyword))
        {
            reasons.Add($"Keyword sugerida para CTA/DM: {suggestedKeyword}.");
            instagramScore += 8;
        }

        if (action == WhatsAppOfferScoutActions.NoAction && score > 0)
        {
            action = WhatsAppOfferScoutActions.Review;
        }

        return new WhatsAppOfferSuggestion
        {
            MessageId = message.MessageId,
            CreatedAt = message.CreatedAtUtc,
            InstanceName = message.InstanceName ?? string.Empty,
            TargetChatId = message.To,
            SourceGroupTitle = candidate?.ChatTitle ?? message.To,
            ProductName = title,
            CaptionPreview = BuildCaptionPreview(caption),
            OfferUrl = offerUrl,
            OriginalOfferUrl = candidate?.OriginalOfferUrl ?? offerUrl,
            ImageUrl = imageUrl,
            MediaKind = mediaKind,
            SuggestedPostType = suggestedPostType,
            RecommendedAction = action,
            Score = Math.Max(score, 0),
            InstagramScore = Math.Max(instagramScore, 0),
            CatalogScore = Math.Max(catalogScore, 0),
            RecentClicks = recentClicks,
            HasImage = !string.IsNullOrWhiteSpace(imageUrl),
            SuggestedKeyword = suggestedKeyword,
            HasExistingDraft = matchingDraft is not null,
            ExistingDraftId = matchingDraft?.Id,
            ExistingDraftStatus = matchingDraft?.Status,
            RequiresLinkConversion = candidate?.RequiresLinkConversion ?? false,
            LinkConversionApplied = candidate?.LinkConversionApplied ?? true,
            IsPrimarySourceGroup = candidate?.IsPrimarySourceGroup ?? true,
            ConversionNote = candidate?.ConversionNote,
            InCatalogDev = inCatalogDev,
            InCatalogProd = inCatalogProd,
            Reasons = reasons,
            Risks = risks
        };
    }

    private static void EnrichWithMemory(WhatsAppOfferSuggestion suggestion, WhatsAppAgentMemoryEntry? memory)
    {
        if (memory is null)
        {
            return;
        }

        suggestion.LastAppliedAction = memory.AppliedAction;
        suggestion.LastOperatorFeedback = memory.OperatorFeedback;
        suggestion.LastOperatorNote = memory.OperatorNote;
        suggestion.LastOutcome = memory.Outcome;
        suggestion.LastDecisionAt = memory.CreatedAtUtc;

        if (!string.IsNullOrWhiteSpace(memory.SuggestedPostType))
        {
            suggestion.SuggestedPostType = memory.SuggestedPostType;
        }

        if (string.Equals(memory.OperatorFeedback, "rejected", StringComparison.OrdinalIgnoreCase))
        {
            suggestion.Score = Math.Max(0, suggestion.Score - 12);
            suggestion.Risks.Add("Operador rejeitou a ultima recomendacao para esta oferta.");
        }
        else if (string.Equals(memory.OperatorFeedback, "edited", StringComparison.OrdinalIgnoreCase))
        {
            suggestion.Risks.Add("Operador precisou editar a recomendacao anterior.");
        }
        else if (string.Equals(memory.OperatorFeedback, "accepted", StringComparison.OrdinalIgnoreCase))
        {
            suggestion.Reasons.Add("Historico recente mostra aceite operacional para oferta semelhante.");
        }
    }

    private static void ApplyConversionGuardrails(WhatsAppOfferSuggestion suggestion)
    {
        if (!suggestion.RequiresLinkConversion)
        {
            return;
        }

        suggestion.RecommendedAction = WhatsAppOfferScoutActions.ConvertLink;
        suggestion.Score = Math.Max(suggestion.Score, 40);
        suggestion.InstagramScore = 0;
        suggestion.CatalogScore = 0;
        if (!string.IsNullOrWhiteSpace(suggestion.ConversionNote))
        {
            suggestion.Reasons.Add(suggestion.ConversionNote);
        }
        suggestion.Risks.Add("Link ainda nao convertido. Draft, catalogo e publicacao ficam bloqueados.");
    }

    private static InstagramPublishDraft? FindMatchingDraft(IReadOnlyList<InstagramPublishDraft> drafts, string offerUrl, string caption)
    {
        return drafts
            .OrderByDescending(x => x.CreatedAt)
            .FirstOrDefault(d =>
            {
                var draftOfferUrl = ResolveEffectiveOfferUrl(d);
                if (!string.IsNullOrWhiteSpace(offerUrl) &&
                    string.Equals(draftOfferUrl, offerUrl, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                return !string.IsNullOrWhiteSpace(caption) &&
                       !string.IsNullOrWhiteSpace(d.Caption) &&
                       NormalizeWhitespace(d.Caption).Equals(NormalizeWhitespace(caption), StringComparison.OrdinalIgnoreCase);
            });
    }

    private static int CountClicks(IReadOnlyList<Domain.Logs.ClickLogEntry> clickLogs, string offerUrl, InstagramPublishDraft? matchingDraft)
    {
        return clickLogs.Count(log =>
            (!string.IsNullOrWhiteSpace(offerUrl) && string.Equals(log.TargetUrl, offerUrl, StringComparison.OrdinalIgnoreCase)) ||
            (matchingDraft is not null && !string.IsNullOrWhiteSpace(log.DraftId) && string.Equals(log.DraftId, matchingDraft.Id, StringComparison.OrdinalIgnoreCase)) ||
            (matchingDraft is not null && !string.IsNullOrWhiteSpace(log.MediaId) && string.Equals(log.MediaId, matchingDraft.MediaId, StringComparison.OrdinalIgnoreCase)));
    }

    private static string BuildSummary(
        int hoursWindow,
        int evaluatedMessages,
        IReadOnlyList<WhatsAppOfferSuggestion> suggestions,
        bool useAiDecision,
        string sourceChannel,
        string targetSelectionMode,
        int anchoredTargetCount,
        int requestedTargetCount)
    {
        var sourceLabel = string.Equals(sourceChannel, "telegram", StringComparison.OrdinalIgnoreCase) ? "Telegram" : "WhatsApp";
        var selectionLabel = string.Equals(targetSelectionMode, WhatsAppOfferScoutSelectionModes.SinceSelection, StringComparison.OrdinalIgnoreCase)
            ? "somente apos a selecao"
            : "historico salvo";
        var coverageText = requestedTargetCount > 0
            ? $" {anchoredTargetCount}/{requestedTargetCount} grupo(s) com ancora persistida."
            : string.Empty;

        if (suggestions.Count == 0)
        {
            return $"Nenhuma oportunidade relevante encontrada a partir dos posts de {sourceLabel} nas ultimas {hoursWindow}h em modo {selectionLabel}.{coverageText}";
        }

        var instagramDrafts = suggestions.Count(x => string.Equals(x.RecommendedAction, WhatsAppOfferScoutActions.CreateInstagramDraft, StringComparison.OrdinalIgnoreCase));
        var catalog = suggestions.Count(x => string.Equals(x.RecommendedAction, WhatsAppOfferScoutActions.AddToCatalog, StringComparison.OrdinalIgnoreCase));
        var review = suggestions.Count - instagramDrafts - catalog;
        var aiCount = suggestions.Count(x => string.Equals(x.DecisionSource, "ai_guarded", StringComparison.OrdinalIgnoreCase));
        var modeText = useAiDecision
            ? $" Modo hibrido: {aiCount} decisao(oes) confirmadas por IA com guardrails."
            : string.Empty;
        return $"Agente avaliou {evaluatedMessages} post(s) de {sourceLabel} em {hoursWindow}h no modo {selectionLabel} e encontrou {suggestions.Count} oportunidade(s): {instagramDrafts} para virar draft de Instagram, {catalog} para catalogo e {review} para revisao.{modeText}{coverageText}";
    }

    private static List<string> BuildWarnings(
        string sourceChannel,
        IReadOnlySet<string> targetChatIds,
        string targetSelectionMode,
        IReadOnlyList<ChannelMonitorSelectionEntry> persistedSelections,
        IReadOnlyList<WhatsAppOutboundLogEntry> messages)
    {
        var warnings = new List<string>();
        if (messages.Count == 0)
        {
            warnings.Add($"Nenhum log outbound salvo para {sourceChannel}. Gere um post real ou use o botao de log de teste.");
        }

        if (targetChatIds.Count > 0 && persistedSelections.Count == 0)
        {
            warnings.Add("Os grupos digitados ainda nao estao persistidos como monitorados.");
        }

        if (string.Equals(targetSelectionMode, WhatsAppOfferScoutSelectionModes.SinceSelection, StringComparison.OrdinalIgnoreCase) &&
            targetChatIds.Count > 0 &&
            !persistedSelections.Any(x => targetChatIds.Contains(x.ChatId)))
        {
            warnings.Add("Modo 'Somente apos selecao' exige grupos salvos primeiro.");
        }

        return warnings;
    }

    private static bool IsGuardrailValid(WhatsAppOfferAiDecision aiDecision, WhatsAppOfferSuggestion suggestion)
    {
        var action = (aiDecision.RecommendedAction ?? string.Empty).Trim().ToLowerInvariant();
        if (action is not
            (WhatsAppOfferScoutActions.ConvertLink
            or WhatsAppOfferScoutActions.CreateInstagramDraft
            or WhatsAppOfferScoutActions.AddToCatalog
            or WhatsAppOfferScoutActions.ReviewAndPublish
            or WhatsAppOfferScoutActions.Review
            or WhatsAppOfferScoutActions.NoAction))
        {
            return false;
        }

        return action switch
        {
            WhatsAppOfferScoutActions.ConvertLink => suggestion.RequiresLinkConversion,
            WhatsAppOfferScoutActions.CreateInstagramDraft => !suggestion.HasExistingDraft,
            WhatsAppOfferScoutActions.AddToCatalog => suggestion.HasExistingDraft &&
                                                     string.Equals(suggestion.ExistingDraftStatus, "published", StringComparison.OrdinalIgnoreCase) &&
                                                     !suggestion.InCatalogDev &&
                                                     !suggestion.InCatalogProd,
            WhatsAppOfferScoutActions.ReviewAndPublish => suggestion.HasExistingDraft &&
                                                          !string.Equals(suggestion.ExistingDraftStatus, "published", StringComparison.OrdinalIgnoreCase),
            _ => true
        };
    }

    private async Task<string?> GenerateAiReasoningAsync(
        Domain.Logs.WhatsAppOutboundLogEntry message,
        WhatsAppOfferSuggestion suggestion,
        AutomationSettings settings,
        CancellationToken cancellationToken)
    {
        var instagramSettings = settings.InstagramPosts ?? new InstagramPostSettings();
        if (!instagramSettings.UseAi)
        {
            return null;
        }

        var prompt = $"""
        Voce e um analista operacional de afiliados.
        Responda em portugues do Brasil, em no maximo 2 frases curtas.
        Explique por que esta oferta enviada no WhatsApp deve ou nao virar acao no Instagram/catalogo.

        Produto: {suggestion.ProductName}
        Acao sugerida: {suggestion.RecommendedAction}
        Score geral: {suggestion.Score}
        Score Instagram: {suggestion.InstagramScore}
        Score Catalogo: {suggestion.CatalogScore}
        Cliques recentes: {suggestion.RecentClicks}
        Tem imagem: {suggestion.HasImage}
        Ja existe draft: {suggestion.HasExistingDraft}
        Ja esta no catalogo DEV: {suggestion.InCatalogDev}
        Ja esta no catalogo PROD: {suggestion.InCatalogProd}
        Keyword sugerida: {suggestion.SuggestedKeyword}
        Texto original do WhatsApp: {(message.Text ?? string.Empty)}
        """;

        var provider = string.IsNullOrWhiteSpace(instagramSettings.AiProvider)
            ? "openai"
            : instagramSettings.AiProvider.Trim().ToLowerInvariant();

        return provider switch
        {
            "gemini" => await _geminiGenerator.GenerateFreeformAsync(prompt, settings.Gemini ?? new GeminiSettings(), cancellationToken),
            "gemma4" => await _geminiGenerator.GenerateFreeformAsync(prompt, GeminiInstagramPostGenerator.WithGeminiKeyFallback(settings.Gemma4, settings.Gemini).AsAdvanced(), cancellationToken),
            "deepseek" => await _deepSeekGenerator.GenerateFreeformAsync(prompt, settings.DeepSeek ?? new DeepSeekSettings(), cancellationToken),
            "nemotron" => await _nemotronGenerator.GenerateFreeformAsync(prompt, settings.Nemotron ?? new NemotronSettings(), cancellationToken),
            "qwen" => await _qwenGenerator.GenerateFreeformAsync(prompt, settings.Qwen ?? new QwenSettings(), cancellationToken),
            "vila" => await _vilaGenerator.GenerateFreeformAsync(prompt, settings.VilaNvidia ?? new VilaNvidiaSettings(), cancellationToken),
            _ => await _openAiGenerator.GenerateFreeformAsync(prompt, settings.OpenAI ?? new OpenAISettings(), cancellationToken)
        };
    }

    private static string BuildProductName(string caption, string offerUrl)
    {
        var lines = Regex.Split(caption ?? string.Empty, @"\r?\n")
            .Select(x => x.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where(x => !x.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (lines.Count > 0)
        {
            return lines[0].Length > 120 ? lines[0][..120] : lines[0];
        }

        if (Uri.TryCreate(offerUrl, UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }

        return "Oferta do WhatsApp";
    }

    private static string BuildCaptionPreview(string caption)
    {
        var normalized = NormalizeWhitespace(caption);
        return normalized.Length <= 160 ? normalized : normalized[..160];
    }

    internal static string BuildSuggestedKeyword(string title, string caption, string offerUrl)
    {
        var baseText = !string.IsNullOrWhiteSpace(title) ? title : caption;
        var tokens = Regex.Matches(baseText ?? string.Empty, @"[\p{L}\p{N}]{3,}", RegexOptions.CultureInvariant)
            .Select(x => x.Value.ToUpperInvariant())
            .Where(x => x.Length >= 4)
            .Where(x => x is not "OFERTA" and not "PROMOCAO" and not "PROMOÇÃO" and not "DESCONTO" and not "LINK")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (tokens.Count > 0)
        {
            var selected = tokens[0];
            return selected.Length > 16 ? selected[..16] : selected;
        }

        if (Uri.TryCreate(offerUrl, UriKind.Absolute, out var uri))
        {
            var host = uri.Host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Split('.')
                .FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(host))
            {
                var normalized = Regex.Replace(host.ToUpperInvariant(), @"[^\p{L}\p{N}]+", string.Empty, RegexOptions.CultureInvariant);
                return normalized.Length > 16 ? normalized[..16] : normalized;
            }
        }

        return "OFERTA";
    }

    internal static string InferSuggestedPostType(WhatsAppOutboundLogEntry message, string? imageUrl = null)
    {
        var mediaKind = InferMediaKind(message);
        if (string.Equals(mediaKind, "video", StringComparison.OrdinalIgnoreCase))
        {
            return WhatsAppOfferScoutPostTypes.Reel;
        }

        if (!string.IsNullOrWhiteSpace(imageUrl) || string.Equals(mediaKind, "image", StringComparison.OrdinalIgnoreCase))
        {
            return WhatsAppOfferScoutPostTypes.Feed;
        }

        return WhatsAppOfferScoutPostTypes.Catalog;
    }

    internal static string InferMediaKind(WhatsAppOutboundLogEntry message)
    {
        var kind = (message.Kind ?? string.Empty).Trim().ToLowerInvariant();
        var mimeType = (message.MimeType ?? string.Empty).Trim().ToLowerInvariant();
        var fileName = (message.FileName ?? string.Empty).Trim().ToLowerInvariant();
        var mediaUrl = (message.MediaUrl ?? string.Empty).Trim().ToLowerInvariant();

        if (kind.Contains("video", StringComparison.OrdinalIgnoreCase) ||
            mimeType.StartsWith("video/", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
            mediaUrl.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
            mediaUrl.Contains(".mp4?", StringComparison.OrdinalIgnoreCase))
        {
            return "video";
        }

        if (!string.IsNullOrWhiteSpace(message.MediaUrl))
        {
            return "image";
        }

        return "text";
    }

    private static bool IsPrimarySourceGroup(string? chatTitle)
        => !string.IsNullOrWhiteSpace(chatTitle) &&
           chatTitle.Contains("rei das ofertas", StringComparison.OrdinalIgnoreCase);

    private static long? TryParseTelegramChatId(string? chatId)
        => long.TryParse(chatId?.Trim(), out var parsed) ? parsed : null;

    private static bool TryGetStrictConvertedText(string originalText, bool conversionSuccess, int convertedLinks, string? convertedText, out string strictText)
    {
        strictText = string.Empty;
        if (!conversionSuccess || convertedLinks <= 0 || string.IsNullOrWhiteSpace(convertedText))
        {
            return false;
        }

        var originalUrls = ExtractNormalizedUrls(originalText);
        if (originalUrls.Count == 0)
        {
            return false;
        }

        var convertedUrls = ExtractNormalizedUrls(convertedText);
        if (convertedUrls.Count == 0)
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

    private static string NormalizeSourceChannel(string? sourceChannel)
    {
        return string.Equals(sourceChannel, "telegram", StringComparison.OrdinalIgnoreCase)
            ? "telegram"
            : "whatsapp";
    }

    private static string NormalizeTargetSelectionMode(string? targetSelectionMode)
    {
        return string.Equals(targetSelectionMode, WhatsAppOfferScoutSelectionModes.SinceSelection, StringComparison.OrdinalIgnoreCase)
            ? WhatsAppOfferScoutSelectionModes.SinceSelection
            : WhatsAppOfferScoutSelectionModes.SavedHistory;
    }

    private static WhatsAppOutboundLogEntry MapTelegramMessage(TelegramOutboundLogEntry entry)
    {
        return new WhatsAppOutboundLogEntry
        {
            MessageId = entry.MessageId,
            CreatedAtUtc = entry.CreatedAtUtc,
            Kind = string.IsNullOrWhiteSpace(entry.ImageUrl) ? "text" : "image-url",
            InstanceName = "telegram",
            To = entry.ChatId.ToString(),
            Text = entry.Text,
            MediaUrl = entry.ImageUrl,
            MimeType = string.IsNullOrWhiteSpace(entry.ImageUrl) ? null : "image/telegram",
            FileName = null
        };
    }

    private static string NormalizeWhitespace(string? value)
        => Regex.Replace(value ?? string.Empty, @"\s+", " ", RegexOptions.CultureInvariant).Trim();

    private static HashSet<string> ExtractNormalizedUrls(string? text)
    {
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Regex.Matches(text ?? string.Empty, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var normalized = match.Value.Trim().TrimEnd('.', ',', ';', ')', ']', '}');
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                urls.Add(normalized);
            }
        }

        return urls;
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

    private static bool LooksLikeOfferText(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return text.Contains("R$", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("oferta", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("cupom", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("desconto", StringComparison.OrdinalIgnoreCase);
    }

    private static string? ResolveEffectiveOfferUrl(InstagramPublishDraft draft)
    {
        if (!string.IsNullOrWhiteSpace(draft.OfferUrl))
        {
            return draft.OfferUrl;
        }

        var ctaLink = draft.Ctas?.Select(x => x.Link).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
        if (!string.IsNullOrWhiteSpace(ctaLink))
        {
            return ctaLink;
        }

        if (!string.IsNullOrWhiteSpace(draft.AutoReplyLink))
        {
            return draft.AutoReplyLink;
        }

        return ExtractFirstUrl(draft.Caption);
    }

    private sealed record ScoutMessageEnvelope(WhatsAppOutboundLogEntry Message, ChannelOfferCandidate Candidate);
}
