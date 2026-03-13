using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.ProductData;
using System.Text.Json;

namespace AchadinhosBot.Next.Application.Services;

public sealed class ChannelOfferDeepAnalysisService : IChannelOfferDeepAnalysisService
{
    private static readonly Regex UrlRegex = new(@"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private readonly IChannelOfferCandidateStore _candidateStore;
    private readonly IWhatsAppAgentMemoryStore _memoryStore;
    private readonly IWhatsAppOutboundLogStore _whatsAppOutboundLogStore;
    private readonly ITelegramOutboundLogStore _telegramOutboundLogStore;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPostComposer _composer;
    private readonly ISettingsStore _settingsStore;
    private readonly IAffiliateLinkService _affiliateLinkService;
    private readonly OfficialProductDataService _officialProductDataService;
    private readonly InstagramLinkMetaService _metaService;
    private readonly OpenAiInstagramPostGenerator _openAiGenerator;
    private readonly GeminiInstagramPostGenerator _geminiGenerator;
    private readonly DeepSeekInstagramPostGenerator _deepSeekGenerator;
    private readonly NemotronInstagramPostGenerator _nemotronGenerator;
    private readonly QwenInstagramPostGenerator _qwenGenerator;
    private readonly VilaNvidiaGenerator _vilaGenerator;

    public ChannelOfferDeepAnalysisService(
        IChannelOfferCandidateStore candidateStore,
        IWhatsAppAgentMemoryStore memoryStore,
        IWhatsAppOutboundLogStore whatsAppOutboundLogStore,
        ITelegramOutboundLogStore telegramOutboundLogStore,
        IInstagramPublishStore publishStore,
        IInstagramPostComposer composer,
        ISettingsStore settingsStore,
        IAffiliateLinkService affiliateLinkService,
        OfficialProductDataService officialProductDataService,
        InstagramLinkMetaService metaService,
        OpenAiInstagramPostGenerator openAiGenerator,
        GeminiInstagramPostGenerator geminiGenerator,
        DeepSeekInstagramPostGenerator deepSeekGenerator,
        NemotronInstagramPostGenerator nemotronGenerator,
        QwenInstagramPostGenerator qwenGenerator,
        VilaNvidiaGenerator vilaGenerator)
    {
        _candidateStore = candidateStore;
        _memoryStore = memoryStore;
        _whatsAppOutboundLogStore = whatsAppOutboundLogStore;
        _telegramOutboundLogStore = telegramOutboundLogStore;
        _publishStore = publishStore;
        _composer = composer;
        _settingsStore = settingsStore;
        _affiliateLinkService = affiliateLinkService;
        _officialProductDataService = officialProductDataService;
        _metaService = metaService;
        _openAiGenerator = openAiGenerator;
        _geminiGenerator = geminiGenerator;
        _deepSeekGenerator = deepSeekGenerator;
        _nemotronGenerator = nemotronGenerator;
        _qwenGenerator = qwenGenerator;
        _vilaGenerator = vilaGenerator;
    }

    public async Task<ChannelOfferDeepAnalysisResult> AnalyzeAsync(ChannelOfferDeepAnalysisRequest request, CancellationToken cancellationToken)
    {
        var sourceChannel = NormalizeSourceChannel(request.SourceChannel);
        var candidate = await _candidateStore.GetAsync(sourceChannel, request.MessageId, cancellationToken);
        var message = await LoadMessageAsync(sourceChannel, request.MessageId, candidate, cancellationToken);
        if (message is null)
        {
            throw new InvalidOperationException("Mensagem da oferta nao encontrada para analise profunda.");
        }

        var sourceText = string.IsNullOrWhiteSpace(candidate?.EffectiveText) ? (message.Text ?? string.Empty) : candidate!.EffectiveText;
        var candidateUrls = ExtractUrls(sourceText);
        if (!string.IsNullOrWhiteSpace(candidate?.EffectiveOfferUrl))
        {
            candidateUrls.Insert(0, candidate!.EffectiveOfferUrl!);
            candidateUrls = candidateUrls
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var selectedOffer = await SelectPrimaryOfferUrlAsync(sourceText, candidateUrls, settings, cancellationToken);
        var originalSelectedOfferUrl = selectedOffer.Url;
        var conversion = await ConvertSelectedOfferUrlAsync(candidate, originalSelectedOfferUrl, cancellationToken);
        var offerUrl = FirstNonEmpty(conversion.ConvertedUrl, originalSelectedOfferUrl) ?? string.Empty;
        var productName = BuildProductName(sourceText, offerUrl);
        var offerContext = BuildOfferContext(sourceText, offerUrl);
        var enrichment = await ResolveDataEnrichmentAsync(sourceText, candidate, offerUrl, candidateUrls, cancellationToken);
        var official = enrichment.Official;
        var meta = enrichment.Meta;
        var effectiveProductName = FirstNonEmpty(official?.Title, meta.Title, productName) ?? productName;

        var captionOptions = await BuildCaptionOptionsAsync(effectiveProductName, offerContext, offerUrl, official, meta, settings.InstagramPosts, cancellationToken);
        var hashtags = await _composer.SuggestHashtagsAsync(effectiveProductName, settings.InstagramPosts, cancellationToken);
        var imageUrls = BuildImageCandidates(candidate, official, meta);
        var videoUrls = BuildVideoCandidates(candidate, official, meta);
        var mediaInsights = await RankMediaInsightsAsync(effectiveProductName, captionOptions.FirstOrDefault() ?? string.Empty, imageUrls, videoUrls, settings, cancellationToken);
        imageUrls = mediaInsights.Where(x => string.Equals(x.Kind, "image", StringComparison.OrdinalIgnoreCase)).Select(x => x.Url).ToList();
        videoUrls = mediaInsights.Where(x => string.Equals(x.Kind, "video", StringComparison.OrdinalIgnoreCase)).Select(x => x.Url).ToList();
        var memoryByMessageId = await _memoryStore.GetLatestByMessageIdsAsync(new[] { request.MessageId }, cancellationToken);
        memoryByMessageId.TryGetValue(request.MessageId, out var latestMemory);
        var suggestedPostType = InferSuggestedPostType(candidate?.MediaKind, imageUrls, videoUrls);
        if (!string.IsNullOrWhiteSpace(latestMemory?.SuggestedPostType))
        {
            suggestedPostType = latestMemory.SuggestedPostType!;
        }
        var suggestedKeyword = BuildSuggestedKeyword(effectiveProductName);
        var reasons = BuildReasons(official, meta, imageUrls, videoUrls, enrichment, mediaInsights, latestMemory);
        var risks = BuildRisks(offerUrl, imageUrls, videoUrls, official, enrichment, mediaInsights);
        var existingDraft = await FindMatchingDraftAsync(offerUrl, sourceText, cancellationToken);
        var recommendedAction = existingDraft is null
            ? WhatsAppOfferScoutActions.CreateInstagramDraft
            : string.Equals(existingDraft.Status, "published", StringComparison.OrdinalIgnoreCase)
                ? WhatsAppOfferScoutActions.AddToCatalog
                : WhatsAppOfferScoutActions.ReviewAndPublish;

        var result = new ChannelOfferDeepAnalysisResult
        {
            SourceChannel = sourceChannel,
            MessageId = request.MessageId,
            RecommendedAction = recommendedAction,
            ProductName = effectiveProductName,
            OfferUrl = offerUrl,
            SelectedOfferUrlReason = BuildSelectedOfferUrlReason(selectedOffer.Reason, conversion),
            OriginalSelectedOfferUrl = originalSelectedOfferUrl,
            OfferUrlWasConverted = conversion.WasConverted,
            OfferUrlConversionNote = conversion.Note,
            CandidateUrls = candidateUrls,
            Store = official?.Store,
            CurrentPrice = FirstNonEmpty(official?.CurrentPrice, meta.PriceText),
            PreviousPrice = FirstNonEmpty(official?.PreviousPrice, meta.PreviousPriceText),
            DiscountPercent = official?.DiscountPercent ?? meta.DiscountPercentFromHtml,
            IsLightningDeal = official?.IsLightningDeal ?? false,
            LightningDealExpiry = official?.LightningDealExpiry,
            EstimatedDelivery = official?.EstimatedDelivery,
            CouponCode = official?.CouponCode,
            CouponDescription = official?.CouponDescription,
            DataSource = FirstNonEmpty(official?.DataSource, meta.ResolvedUrl is not null ? "meta" : null),
            UrlSelectionConfidence = selectedOffer.Confidence,
            DataQualityScore = ComputeDataQualityScore(official, meta, imageUrls, videoUrls, enrichment),
            ScraperFallbackApplied = enrichment.ScraperFallbackApplied,
            FallbacksUsed = enrichment.FallbacksUsed.ToList(),
            SuggestedPostType = suggestedPostType,
            SuggestedKeyword = suggestedKeyword,
            Score = ComputeScore(official, imageUrls, videoUrls, existingDraft),
            InstagramScore = ComputeInstagramScore(official, imageUrls, videoUrls),
            CatalogScore = ComputeCatalogScore(official, existingDraft),
            PrimaryImageUrl = imageUrls.FirstOrDefault(),
            PrimaryVideoUrl = videoUrls.FirstOrDefault(),
            ImageUrls = imageUrls,
            VideoUrls = videoUrls,
            MediaInsights = mediaInsights,
            CaptionOptions = captionOptions,
            Caption = captionOptions.FirstOrDefault() ?? string.Empty,
            Hashtags = hashtags,
            CtaKeywords = BuildCtaKeywords(suggestedKeyword, productName),
            Reasons = reasons,
            Risks = risks,
            AiReasoning = request.UseAiReasoning
                ? await BuildDeepReasoningAsync(
                    sourceText,
                    effectiveProductName,
                    offerUrl,
                    selectedOffer.Reason,
                    conversion,
                    official,
                    meta,
                    suggestedPostType,
                    suggestedKeyword,
                    reasons,
                    risks,
                    enrichment,
                    settings,
                    cancellationToken)
                : null,
            SourceText = sourceText,
            OfferType = official?.IsLightningDeal == true ? "flash" : "catalog",
            LastOperatorFeedback = latestMemory?.OperatorFeedback,
            LastOperatorNote = latestMemory?.OperatorNote,
            LastAppliedAction = latestMemory?.AppliedAction,
            LastOutcome = latestMemory?.Outcome,
            LastDecisionAt = latestMemory?.CreatedAtUtc
        };

        await PersistCandidateConversionAsync(candidate, sourceText, originalSelectedOfferUrl, conversion, cancellationToken);

        if (!request.CreateDraft)
        {
            return result;
        }

        var draft = existingDraft ?? new InstagramPublishDraft();
        ApplyAnalysisToDraft(draft, result);
        if (existingDraft is null)
        {
            await _publishStore.SaveAsync(draft, cancellationToken);
        }
        else
        {
            await _publishStore.UpdateAsync(draft, cancellationToken);
        }

        result.DraftId = draft.Id;
        result.EditorUrl = $"/conversor-admin?draftId={draft.Id}";
        return result;
    }

    private async Task<WhatsAppOutboundLogEntry?> LoadMessageAsync(
        string sourceChannel,
        string messageId,
        ChannelOfferCandidate? candidate,
        CancellationToken cancellationToken)
    {
        if (string.Equals(sourceChannel, "telegram", StringComparison.OrdinalIgnoreCase))
        {
            var telegramItems = await _telegramOutboundLogStore.ListRecentAsync(500, cancellationToken);
            var telegram = telegramItems.FirstOrDefault(x => string.Equals(x.MessageId, messageId, StringComparison.OrdinalIgnoreCase));
            if (telegram is not null)
            {
                return MapTelegram(telegram, candidate);
            }

            if (candidate is not null)
            {
                return BuildMessageFromCandidate(candidate);
            }

            return null;
        }

        return candidate is not null
            ? await _whatsAppOutboundLogStore.GetAsync(messageId, cancellationToken) ?? BuildMessageFromCandidate(candidate)
            : await _whatsAppOutboundLogStore.GetAsync(messageId, cancellationToken);
    }

    private static WhatsAppOutboundLogEntry MapTelegram(TelegramOutboundLogEntry entry, ChannelOfferCandidate? candidate)
    {
        var mediaKind = !string.IsNullOrWhiteSpace(entry.ImageUrl) ? "image" : "text";
        return new WhatsAppOutboundLogEntry
        {
            MessageId = entry.MessageId,
            CreatedAtUtc = entry.CreatedAtUtc,
            Kind = mediaKind,
            InstanceName = "telegram-userbot",
            To = entry.ChatId.ToString(),
            Text = string.IsNullOrWhiteSpace(candidate?.EffectiveText) ? entry.Text : candidate!.EffectiveText,
            MediaUrl = entry.ImageUrl,
            MimeType = mediaKind == "image" ? "image/telegram" : null
        };
    }

    private static WhatsAppOutboundLogEntry BuildMessageFromCandidate(ChannelOfferCandidate candidate)
    {
        return new WhatsAppOutboundLogEntry
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

    private async Task<List<string>> BuildCaptionOptionsAsync(
        string productName,
        string offerContext,
        string offerUrl,
        OfficialProductDataResult? official,
        LinkMetaResult meta,
        InstagramPostSettings settings,
        CancellationToken cancellationToken)
    {
        var options = new List<string>();
        var aiCaption = await _composer.BuildAsync(productName, offerContext, settings, cancellationToken);
        AddStructuredCaptions(options, aiCaption);

        var priceLine = FirstNonEmpty(official?.CurrentPrice, meta.PriceText);
        var previousPrice = FirstNonEmpty(official?.PreviousPrice, meta.PreviousPriceText);
        var discount = official?.DiscountPercent ?? meta.DiscountPercentFromHtml;
        var title = FirstNonEmpty(official?.Title, meta.Title, productName) ?? productName;

        AddIfUseful(options, BuildCaptionVariant(title, priceLine, previousPrice, discount, offerUrl, "oferta"));
        AddIfUseful(options, BuildCaptionVariant(title, priceLine, previousPrice, discount, offerUrl, "urgencia"));
        AddIfUseful(options, BuildCaptionVariant(title, priceLine, previousPrice, discount, offerUrl, "social"));

        return options
            .Select(x => x.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToList();
    }

    private static void AddStructuredCaptions(List<string> options, string? rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return;
        }

        var extracted = ExtractCaptionSections(rawText);
        if (extracted.Count > 0)
        {
            foreach (var caption in extracted)
            {
                AddIfUseful(options, caption);
            }

            return;
        }

        AddIfUseful(options, rawText);
    }

    private static List<string> ExtractCaptionSections(string rawText)
    {
        var result = new List<string>();
        var lines = rawText.Replace("\r", string.Empty)
            .Split('\n', StringSplitOptions.TrimEntries)
            .ToList();

        var current = new List<string>();
        var insideCaption = false;

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                if (insideCaption)
                {
                    current.Add(string.Empty);
                }

                continue;
            }

            if (IsCaptionHeader(line))
            {
                FlushCaption(result, current);
                insideCaption = true;
                continue;
            }

            if (IsStructuredOutputBoundary(line))
            {
                FlushCaption(result, current);
                insideCaption = false;
                continue;
            }

            if (insideCaption)
            {
                current.Add(line);
            }
        }

        FlushCaption(result, current);
        return result;
    }

    private static bool IsCaptionHeader(string line)
    {
        return Regex.IsMatch(line, @"^Legenda\s+\d+\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static bool IsStructuredOutputBoundary(string line)
    {
        return line.StartsWith("POST PARA INSTAGRAM", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Produto:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Link afiliado:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Melhor variacao sugerida:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Melhor variação sugerida:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Hashtags sugeridas:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Sugestoes de imagem:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Sugestões de imagem:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Beneficios em bullet points:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Benefícios em bullet points:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Sugestao rapida", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Sugestão rápida", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Post extra", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Imagens encontradas", StringComparison.OrdinalIgnoreCase);
    }

    private static void FlushCaption(List<string> result, List<string> current)
    {
        if (current.Count == 0)
        {
            return;
        }

        var caption = string.Join("\n", current).Trim();
        current.Clear();

        if (!string.IsNullOrWhiteSpace(caption))
        {
            result.Add(caption);
        }
    }

    private static string BuildCaptionVariant(string title, string? priceLine, string? previousPrice, int? discount, string offerUrl, string style)
    {
        var priceText = !string.IsNullOrWhiteSpace(priceLine) ? $"Preco atual: {priceLine}" : "Preco sob consulta.";
        var previousText = !string.IsNullOrWhiteSpace(previousPrice) ? $" De: {previousPrice}." : string.Empty;
        var discountText = discount.HasValue && discount.Value > 0 ? $" Desconto aproximado: {discount.Value}%." : string.Empty;

        return style switch
        {
            "urgencia" => $"OFERTA EM ALERTA\n\n{title}\n{priceText}.{previousText}{discountText}\n\nSe fizer sentido para voce, vale agir rapido porque esse tipo de item gira depressa.\n\nComente EU QUERO para receber o link ou abra a oferta:\n{offerUrl}",
            "social" => $"ACHADO QUE MERECE SALVAR\n\n{title}\n{priceText}.{previousText}{discountText}\n\nBom candidato para catalogo e repost, com potencial de clique.\n\nQuer o link? Comente EU QUERO ou use:\n{offerUrl}",
            _ => $"OFERTA SELECIONADA\n\n{title}\n{priceText}.{previousText}{discountText}\n\nItem pronto para revisao e publicacao, com CTA claro para DM e catalogo.\n\nLink da oferta:\n{offerUrl}"
        };
    }

    private static List<string> BuildImageCandidates(ChannelOfferCandidate? candidate, OfficialProductDataResult? official, LinkMetaResult meta)
    {
        var items = new List<string>();
        AddDistinct(items, candidate?.MediaKind == "image" ? candidate.MediaUrl : null);
        foreach (var image in official?.Images ?? Enumerable.Empty<string>())
        {
            AddDistinct(items, image);
        }
        foreach (var image in meta.Images)
        {
            AddDistinct(items, image);
        }
        return items.Take(10).ToList();
    }

    private static List<string> BuildVideoCandidates(ChannelOfferCandidate? candidate, OfficialProductDataResult? official, LinkMetaResult meta)
    {
        var items = new List<string>();
        AddDistinct(items, candidate?.MediaKind == "video" ? candidate.MediaUrl : null);
        AddDistinct(items, official?.VideoUrl);
        foreach (var video in meta.Videos)
        {
            AddDistinct(items, video);
        }
        return items.Take(6).ToList();
    }

    private async Task<List<OfferMediaInsight>> RankMediaInsightsAsync(
        string productName,
        string caption,
        IReadOnlyList<string> imageUrls,
        IReadOnlyList<string> videoUrls,
        AutomationSettings settings,
        CancellationToken cancellationToken)
    {
        var insights = new List<OfferMediaInsight>();

        foreach (var url in videoUrls.Where(x => !string.IsNullOrWhiteSpace(x)).Take(4))
        {
            insights.Add(new OfferMediaInsight
            {
                Url = url,
                Kind = "video",
                Score = 82,
                IsMatch = true,
                Reason = "Video candidato priorizado para reel e demonstracao visual.",
                StyleNotes = "Use abertura curta, movimento e CTA mais rapido."
            });
        }

        foreach (var url in imageUrls.Where(x => !string.IsNullOrWhiteSpace(x)).Take(8))
        {
            var insight = new OfferMediaInsight
            {
                Url = url,
                Kind = "image",
                Score = 58,
                IsMatch = true,
                Reason = "Imagem reaproveitavel para criativo.",
                StyleNotes = "Boa base para catalogo ou carrossel."
            };

            var evaluation = await _vilaGenerator.EvaluateImageMatchAsync(productName, caption, url, settings.VilaNvidia ?? new VilaNvidiaSettings(), cancellationToken);
            if (evaluation is not null)
            {
                insight.Score = Math.Clamp(evaluation.Value.Score, 0, 100);
                insight.IsMatch = evaluation.Value.IsMatch;
                insight.Reason = string.IsNullOrWhiteSpace(evaluation.Value.Reason)
                    ? insight.Reason
                    : evaluation.Value.Reason;
                insight.StyleNotes = evaluation.Value.IsMatch
                    ? "VILA validou boa aderencia visual ao produto."
                    : "VILA detectou aderencia fraca; use apenas se nao houver opcao melhor.";
            }

            insights.Add(insight);
        }

        var ordered = insights
            .OrderByDescending(x => x.IsMatch)
            .ThenByDescending(x => x.Score)
            .ThenBy(x => x.Kind)
            .ToList();

        if (ordered.Count > 0)
        {
            ordered[0].IsPrimary = true;
        }

        return ordered;
    }

    private async Task<InstagramPublishDraft?> FindMatchingDraftAsync(string offerUrl, string sourceText, CancellationToken cancellationToken)
    {
        var drafts = await _publishStore.ListAsync(cancellationToken);
        return drafts
            .OrderByDescending(x => x.CreatedAt)
            .FirstOrDefault(x =>
                (!string.IsNullOrWhiteSpace(offerUrl) && string.Equals(ResolveEffectiveOfferUrl(x), offerUrl, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrWhiteSpace(sourceText) && string.Equals(NormalizeWhitespace(x.Caption), NormalizeWhitespace(sourceText), StringComparison.OrdinalIgnoreCase)));
    }

    private static void ApplyAnalysisToDraft(InstagramPublishDraft draft, ChannelOfferDeepAnalysisResult result)
    {
        var isReel = string.Equals(result.SuggestedPostType, WhatsAppOfferScoutPostTypes.Reel, StringComparison.OrdinalIgnoreCase);
        draft.ProductName = result.ProductName;
        draft.Caption = result.Caption;
        draft.CaptionOptions = result.CaptionOptions.ToList();
        draft.SelectedCaptionIndex = draft.CaptionOptions.Count > 0 ? 1 : 0;
        draft.Hashtags = result.Hashtags;
        draft.OfferUrl = result.OfferUrl;
        draft.PostType = isReel ? "reel" : "feed";
        draft.VideoUrl = isReel ? result.PrimaryVideoUrl : draft.VideoUrl;
        draft.ImageUrls = isReel
            ? draft.ImageUrls
            : result.ImageUrls.Take(10).ToList();
        draft.Ctas = result.CtaKeywords
            .Select(keyword => new InstagramCtaOption { Keyword = keyword, Link = result.OfferUrl })
            .ToList();
        draft.AutoReplyEnabled = !string.IsNullOrWhiteSpace(result.OfferUrl);
        draft.AutoReplyKeyword = result.CtaKeywords.FirstOrDefault();
        draft.AutoReplyLink = result.OfferUrl;
        draft.Status = string.Equals(draft.Status, "published", StringComparison.OrdinalIgnoreCase) ? draft.Status : "draft";
        draft.Store = result.Store;
        draft.CurrentPrice = result.CurrentPrice;
        draft.PreviousPrice = result.PreviousPrice;
        draft.DiscountPercent = result.DiscountPercent;
        draft.EstimatedDelivery = result.EstimatedDelivery;
        draft.IsLightningDeal = result.IsLightningDeal;
        draft.LightningDealExpiry = result.LightningDealExpiry;
        draft.CouponCode = result.CouponCode;
        draft.CouponDescription = result.CouponDescription;
        draft.SourceDataOrigin = result.DataSource;
        draft.SuggestedImageUrls = result.ImageUrls.ToList();
        draft.SuggestedVideoUrls = result.VideoUrls.ToList();
    }

    private static List<string> BuildReasons(OfficialProductDataResult? official, LinkMetaResult meta, IReadOnlyCollection<string> imageUrls, IReadOnlyCollection<string> videoUrls, DataEnrichmentResult enrichment, IReadOnlyCollection<OfferMediaInsight> mediaInsights, WhatsAppAgentMemoryEntry? latestMemory)
    {
        var reasons = new List<string>();
        if (!string.IsNullOrWhiteSpace(official?.CurrentPrice) || !string.IsNullOrWhiteSpace(meta.PriceText))
        {
            reasons.Add("A oferta tem preco identificado, o que melhora CTA e conversao.");
        }
        if ((official?.DiscountPercent ?? meta.DiscountPercentFromHtml) > 0)
        {
            reasons.Add("Ha sinal de desconto, util para urgencia e destaque visual.");
        }
        if (imageUrls.Count > 0)
        {
            reasons.Add("Foi encontrado material visual para montar criativo e carrossel.");
        }
        if (videoUrls.Count > 0)
        {
            reasons.Add("Existe video candidato, abrindo possibilidade de reel pronto.");
        }
        if (!string.IsNullOrWhiteSpace(official?.EstimatedDelivery))
        {
            reasons.Add("Informacao de entrega disponivel para reforcar decisao de compra.");
        }
        if (enrichment.ScraperFallbackApplied)
        {
            reasons.Add("Fallback por scraper entrou em acao para completar dados da oferta.");
        }
        var bestMedia = mediaInsights.OrderByDescending(x => x.Score).FirstOrDefault();
        if (bestMedia is not null)
        {
            reasons.Add($"Melhor midia ranqueada com score {bestMedia.Score}/100: {bestMedia.Reason}");
        }
        if (!string.IsNullOrWhiteSpace(latestMemory?.OperatorFeedback))
        {
            reasons.Add($"Historico do operador nesta oferta: {latestMemory.OperatorFeedback}.");
        }
        return reasons;
    }

    private static List<string> BuildRisks(string offerUrl, IReadOnlyCollection<string> imageUrls, IReadOnlyCollection<string> videoUrls, OfficialProductDataResult? official, DataEnrichmentResult enrichment, IReadOnlyCollection<OfferMediaInsight> mediaInsights)
    {
        var risks = new List<string>();
        if (string.IsNullOrWhiteSpace(offerUrl))
        {
            risks.Add("Nao foi possivel confirmar o link final da oferta.");
        }
        if (imageUrls.Count == 0 && videoUrls.Count == 0)
        {
            risks.Add("Nenhuma midia forte foi encontrada para o workspace.");
        }
        if (string.IsNullOrWhiteSpace(official?.CurrentPrice))
        {
            risks.Add("Preco oficial nao confirmado; revisar antes de disparar.");
        }
        if (enrichment.ScraperFallbackApplied && official?.IsOfficial != true)
        {
            risks.Add("Parte dos dados veio de fallback por scraper; confirmar titulo e preco antes de publicar em massa.");
        }
        if (mediaInsights.Any() && mediaInsights.All(x => x.Score < 55))
        {
            risks.Add("As midias encontradas tiveram score visual baixo; vale revisar antes de publicar.");
        }
        return risks;
    }

    private static int ComputeDataQualityScore(OfficialProductDataResult? official, LinkMetaResult meta, IReadOnlyCollection<string> imageUrls, IReadOnlyCollection<string> videoUrls, DataEnrichmentResult enrichment)
    {
        var score = 10;
        if (!string.IsNullOrWhiteSpace(official?.Title) || !string.IsNullOrWhiteSpace(meta.Title)) score += 18;
        if (!string.IsNullOrWhiteSpace(official?.CurrentPrice) || !string.IsNullOrWhiteSpace(meta.PriceText)) score += 20;
        if ((official?.DiscountPercent ?? meta.DiscountPercentFromHtml ?? 0) > 0) score += 10;
        if (imageUrls.Count > 0) score += 18;
        if (videoUrls.Count > 0) score += 8;
        if (!string.IsNullOrWhiteSpace(official?.EstimatedDelivery)) score += 8;
        if (official?.IsOfficial == true) score += 10;
        if (enrichment.ScraperFallbackApplied) score += 6;
        return Math.Min(score, 100);
    }

    private static int ComputeScore(OfficialProductDataResult? official, IReadOnlyCollection<string> imageUrls, IReadOnlyCollection<string> videoUrls, InstagramPublishDraft? existingDraft)
    {
        var score = 20;
        if (!string.IsNullOrWhiteSpace(official?.CurrentPrice)) score += 20;
        if ((official?.DiscountPercent ?? 0) > 0) score += 12;
        if (imageUrls.Count > 0) score += 18;
        if (videoUrls.Count > 0) score += 10;
        if (existingDraft is not null) score += 8;
        return Math.Min(score, 100);
    }

    private static int ComputeInstagramScore(OfficialProductDataResult? official, IReadOnlyCollection<string> imageUrls, IReadOnlyCollection<string> videoUrls)
    {
        var score = 10;
        if (imageUrls.Count > 0) score += 35;
        if (videoUrls.Count > 0) score += 15;
        if (!string.IsNullOrWhiteSpace(official?.CurrentPrice)) score += 15;
        if ((official?.DiscountPercent ?? 0) > 0) score += 10;
        return Math.Min(score, 100);
    }

    private static int ComputeCatalogScore(OfficialProductDataResult? official, InstagramPublishDraft? existingDraft)
    {
        var score = 15;
        if (!string.IsNullOrWhiteSpace(official?.CurrentPrice)) score += 20;
        if (!string.IsNullOrWhiteSpace(official?.Title)) score += 15;
        if (existingDraft is not null) score += 15;
        return Math.Min(score, 100);
    }

    private static string InferSuggestedPostType(string? mediaKind, IReadOnlyCollection<string> imageUrls, IReadOnlyCollection<string> videoUrls)
    {
        if (string.Equals(mediaKind, "video", StringComparison.OrdinalIgnoreCase) || videoUrls.Count > 0)
        {
            return WhatsAppOfferScoutPostTypes.Reel;
        }

        return imageUrls.Count > 1 ? WhatsAppOfferScoutPostTypes.Feed : WhatsAppOfferScoutPostTypes.Feed;
    }

    private static List<string> BuildCtaKeywords(string suggestedKeyword, string productName)
    {
        var values = new List<string>();
        AddDistinct(values, suggestedKeyword);
        AddDistinct(values, "eu quero");
        AddDistinct(values, SimplifyKeyword(productName));
        return values.Take(3).ToList();
    }

    private static string BuildSuggestedKeyword(string productName)
        => SimplifyKeyword(productName);

    private static string SimplifyKeyword(string text)
    {
        var token = NormalizeWhitespace(text)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault() ?? "link";
        token = new string(token.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        return string.IsNullOrWhiteSpace(token) ? "link" : token[..Math.Min(18, token.Length)];
    }

    private static string BuildProductName(string sourceText, string? offerUrl)
    {
        var firstLine = sourceText
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(x => !x.StartsWith("http", StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(firstLine))
        {
            return firstLine.Length > 140 ? firstLine[..140] : firstLine;
        }

        if (Uri.TryCreate(offerUrl, UriKind.Absolute, out var uri))
        {
            return uri.Host.Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        return "Oferta do canal";
    }

    private static string BuildOfferContext(string sourceText, string offerUrl)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(sourceText))
        {
            parts.Add(sourceText.Trim());
        }
        if (!string.IsNullOrWhiteSpace(offerUrl))
        {
            parts.Add($"Link: {offerUrl}");
        }
        return string.Join("\n", parts);
    }

    private static string? ResolveEffectiveOfferUrl(InstagramPublishDraft draft)
    {
        if (!string.IsNullOrWhiteSpace(draft.OfferUrl))
        {
            return draft.OfferUrl;
        }

        var ctaLink = draft.Ctas.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.Link))?.Link;
        if (!string.IsNullOrWhiteSpace(ctaLink))
        {
            return ctaLink;
        }

        return draft.AutoReplyLink;
    }

    private async Task<(string? ConvertedUrl, bool WasConverted, string Note)> ConvertSelectedOfferUrlAsync(
        ChannelOfferCandidate? candidate,
        string? selectedOfferUrl,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(selectedOfferUrl))
        {
            return (null, false, "Nenhuma URL principal foi identificada para conversao.");
        }

        var shouldAttemptConversion =
            candidate?.RequiresLinkConversion == true ||
            string.IsNullOrWhiteSpace(candidate?.EffectiveOfferUrl) ||
            string.Equals(candidate?.OriginalOfferUrl, selectedOfferUrl, StringComparison.OrdinalIgnoreCase);

        if (!shouldAttemptConversion)
        {
            return (selectedOfferUrl, false, "URL principal ja estava pronta para analise.");
        }

        var converted = await _affiliateLinkService.ConvertAsync(selectedOfferUrl, cancellationToken, "agent_deep_analysis");
        if (converted.Success && converted.IsAffiliated && !string.IsNullOrWhiteSpace(converted.ConvertedUrl))
        {
            var note = converted.CorrectionApplied && !string.IsNullOrWhiteSpace(converted.CorrectionNote)
                ? $"URL principal convertida com afiliacao. {converted.CorrectionNote}"
                : "URL principal convertida com afiliacao para analise profunda.";
            return (converted.ConvertedUrl.Trim(), true, note);
        }

        var fallbackReason = FirstNonEmpty(converted.ValidationError, converted.Error) ?? "Conversao nao confirmou um link afiliado valido.";
        return (selectedOfferUrl, false, $"A analise seguiu com a URL original porque a conversao falhou: {fallbackReason}");
    }

    private async Task PersistCandidateConversionAsync(
        ChannelOfferCandidate? candidate,
        string sourceText,
        string? originalSelectedOfferUrl,
        (string? ConvertedUrl, bool WasConverted, string Note) conversion,
        CancellationToken cancellationToken)
    {
        if (candidate is null || string.IsNullOrWhiteSpace(conversion.ConvertedUrl))
        {
            return;
        }

        candidate.EffectiveOfferUrl = conversion.ConvertedUrl;
        candidate.ConversionNote = conversion.Note;

        if (conversion.WasConverted)
        {
            candidate.RequiresLinkConversion = false;
            candidate.LinkConversionApplied = true;
        }

        if (!string.IsNullOrWhiteSpace(originalSelectedOfferUrl) &&
            !string.Equals(originalSelectedOfferUrl, conversion.ConvertedUrl, StringComparison.OrdinalIgnoreCase))
        {
            candidate.EffectiveText = ReplaceFirst(sourceText, originalSelectedOfferUrl, conversion.ConvertedUrl!);
        }
        else if (string.IsNullOrWhiteSpace(candidate.EffectiveText))
        {
            candidate.EffectiveText = sourceText;
        }

        await _candidateStore.UpsertManyAsync(new[] { candidate }, cancellationToken);
    }

    private async Task<DataEnrichmentResult> ResolveDataEnrichmentAsync(
        string sourceText,
        ChannelOfferCandidate? candidate,
        string offerUrl,
        IReadOnlyList<string> candidateUrls,
        CancellationToken cancellationToken)
    {
        var attemptedUrls = new List<string>();
        var fallbackNotes = new List<string>();
        OfficialProductDataResult? bestOfficial = null;
        LinkMetaResult bestMeta = new();

        async Task ProbeAsync(string? url, string note)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return;
            }

            AddDistinct(attemptedUrls, url);

            OfficialProductDataResult? official = null;
            LinkMetaResult meta = new();

            try
            {
                official = await _officialProductDataService.TryGetBestAsync(url, url, cancellationToken);
            }
            catch
            {
                official = null;
            }

            try
            {
                meta = await _metaService.GetMetaAsync(url, cancellationToken);
            }
            catch
            {
                meta = new();
            }

            if (IsBetterOfficialCandidate(official, bestOfficial))
            {
                bestOfficial = official;
                if (!string.IsNullOrWhiteSpace(note))
                {
                    AddDistinct(fallbackNotes, note);
                }
            }

            if (IsBetterMetaCandidate(meta, bestMeta))
            {
                bestMeta = meta;
                if (!string.IsNullOrWhiteSpace(note))
                {
                    AddDistinct(fallbackNotes, $"{note} via metadata.");
                }
            }
        }

        await ProbeAsync(offerUrl, "URL principal analisada.");

        var needsFallback = DataLooksWeak(bestOfficial, bestMeta);
        if (needsFallback && !string.IsNullOrWhiteSpace(candidate?.EffectiveOfferUrl) &&
            !string.Equals(candidate.EffectiveOfferUrl, offerUrl, StringComparison.OrdinalIgnoreCase))
        {
            await ProbeAsync(candidate.EffectiveOfferUrl, "Fallback pela URL efetiva salva no candidato.");
        }

        if (needsFallback && !string.IsNullOrWhiteSpace(candidate?.OriginalOfferUrl) &&
            !string.Equals(candidate.OriginalOfferUrl, offerUrl, StringComparison.OrdinalIgnoreCase))
        {
            await ProbeAsync(candidate.OriginalOfferUrl, "Fallback pela URL original da mensagem.");
        }

        if (needsFallback)
        {
            foreach (var extraUrl in candidateUrls.Where(url => !string.Equals(url, offerUrl, StringComparison.OrdinalIgnoreCase)).Take(4))
            {
                await ProbeAsync(extraUrl, $"Fallback por URL candidata adicional: {extraUrl}");
                if (!DataLooksWeak(bestOfficial, bestMeta))
                {
                    break;
                }
            }
        }

        if (needsFallback && ExtractFirstUrl(sourceText) is { } firstUrl &&
            !attemptedUrls.Contains(firstUrl, StringComparer.OrdinalIgnoreCase))
        {
            await ProbeAsync(firstUrl, "Fallback pela primeira URL encontrada no texto.");
        }

        return new DataEnrichmentResult(
            bestOfficial,
            bestMeta,
            attemptedUrls,
            fallbackNotes,
            attemptedUrls.Count > 1 || fallbackNotes.Any(note => note.Contains("Fallback", StringComparison.OrdinalIgnoreCase)));
    }

    private async Task<string> BuildDeepReasoningAsync(
        string sourceText,
        string productName,
        string offerUrl,
        string selectionReason,
        (string? ConvertedUrl, bool WasConverted, string Note) conversion,
        OfficialProductDataResult? official,
        LinkMetaResult meta,
        string suggestedPostType,
        string suggestedKeyword,
        IReadOnlyList<string> reasons,
        IReadOnlyList<string> risks,
        DataEnrichmentResult enrichment,
        AutomationSettings settings,
        CancellationToken cancellationToken)
    {
        var deterministic = BuildDeterministicReasoning(productName, offerUrl, selectionReason, conversion, official, meta, suggestedPostType, suggestedKeyword, reasons, risks, enrichment);
        var instagramSettings = settings.InstagramPosts ?? new InstagramPostSettings();
        if (!instagramSettings.UseAi)
        {
            return deterministic;
        }

        var provider = string.IsNullOrWhiteSpace(instagramSettings.AiProvider)
            ? "openai"
            : instagramSettings.AiProvider.Trim().ToLowerInvariant();

        var prompt = $$"""
        Voce e um analista senior de ofertas para operacao de afiliados.
        Resuma em portugues, em no maximo 6 linhas objetivas, a analise abaixo.
        Inclua:
        - qual URL foi escolhida e por que
        - se houve conversao afiliada
        - se a oferta parece boa
        - melhor destino operacional (feed, reel, catalogo, bio)
        - CTA sugerido
        - principais riscos

        Produto: {{productName}}
        Texto fonte: {{sourceText}}
        URL final: {{offerUrl}}
        Motivo da URL: {{selectionReason}}
        Conversao: {{conversion.Note}}
        Loja: {{official?.Store ?? "-"}}
        Preco atual: {{official?.CurrentPrice ?? meta.PriceText ?? "-"}}
        Preco anterior: {{official?.PreviousPrice ?? meta.PreviousPriceText ?? "-"}}
        Desconto: {{(official?.DiscountPercent ?? meta.DiscountPercentFromHtml)?.ToString() ?? "-"}}
        Oferta relampago: {{(official?.IsLightningDeal ?? false)}}
        Post type sugerido: {{suggestedPostType}}
        CTA sugerido: {{suggestedKeyword}}
        Motivos: {{string.Join(" | ", reasons)}}
        Riscos: {{string.Join(" | ", risks)}}
        Fallbacks usados: {{string.Join(" | ", enrichment.FallbacksUsed)}}
        """;

        var generated = await GenerateAiTextAsync(prompt, provider, settings, cancellationToken);
        return string.IsNullOrWhiteSpace(generated) ? deterministic : generated.Trim();
    }

    private static string BuildDeterministicReasoning(
        string productName,
        string offerUrl,
        string selectionReason,
        (string? ConvertedUrl, bool WasConverted, string Note) conversion,
        OfficialProductDataResult? official,
        LinkMetaResult meta,
        string suggestedPostType,
        string suggestedKeyword,
        IReadOnlyList<string> reasons,
        IReadOnlyList<string> risks,
        DataEnrichmentResult enrichment)
    {
        var lines = new List<string>
        {
            $"Produto analisado: {productName}.",
            $"URL final usada: {offerUrl}.",
            selectionReason,
            conversion.Note,
            $"Destino sugerido: {suggestedPostType} com CTA {suggestedKeyword}.",
            $"Preco atual: {FirstNonEmpty(official?.CurrentPrice, meta.PriceText) ?? "-"} | desconto: {(official?.DiscountPercent ?? meta.DiscountPercentFromHtml)?.ToString() ?? "-"}.",
            enrichment.ScraperFallbackApplied ? $"Fallbacks usados: {string.Join(" | ", enrichment.FallbacksUsed.Take(3))}." : "Fallbacks usados: nao foi necessario acionar scraper adicional.",
            reasons.Count > 0 ? $"Sinais positivos: {string.Join(" | ", reasons.Take(3))}." : "Sinais positivos: sem destaque forte.",
            risks.Count > 0 ? $"Riscos principais: {string.Join(" | ", risks.Take(3))}." : "Riscos principais: nenhum risco adicional relevante."
        };

        return string.Join(Environment.NewLine, lines.Where(x => !string.IsNullOrWhiteSpace(x)));
    }

    private static string BuildSelectedOfferUrlReason(
        string selectionReason,
        (string? ConvertedUrl, bool WasConverted, string Note) conversion)
    {
        if (string.IsNullOrWhiteSpace(selectionReason))
        {
            return conversion.Note;
        }

        return $"{selectionReason} {conversion.Note}".Trim();
    }

    private static string ReplaceFirst(string text, string search, string replacement)
    {
        if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(search))
        {
            return text;
        }

        var index = text.IndexOf(search, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return text;
        }

        return string.Concat(text.AsSpan(0, index), replacement, text.AsSpan(index + search.Length));
    }

    private static string NormalizeWhitespace(string? text)
        => string.Join(' ', (text ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static string? ExtractFirstUrl(string? text)
        => ExtractUrls(text).FirstOrDefault();

    private static List<string> ExtractUrls(string? text)
        => UrlRegex.Matches(text ?? string.Empty)
            .Select(x => x.Value.Trim().TrimEnd('.', ',', ';', ')', ']'))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private async Task<(string? Url, string Reason, int Confidence)> SelectPrimaryOfferUrlAsync(
        string sourceText,
        IReadOnlyList<string> urls,
        AutomationSettings settings,
        CancellationToken cancellationToken)
    {
        if (urls.Count == 0)
        {
            return (null, "Nenhuma URL encontrada no texto.", 0);
        }

        var aiSelection = await SelectPrimaryOfferUrlWithAiAsync(sourceText, urls, settings, cancellationToken);
        if (!string.IsNullOrWhiteSpace(aiSelection.Url))
        {
            var correctedAiSelection = OverrideCouponLikeSelection(sourceText, urls, aiSelection.Url!, $"URL principal ajustada apos validacao anti-cupom. {aiSelection.Reason}");
            return correctedAiSelection.Url is not null
                ? (correctedAiSelection.Url, correctedAiSelection.Reason, 76)
                : (aiSelection.Url, aiSelection.Reason, 84);
        }

        var scored = urls
            .Select((url, index) => new
            {
                Url = url,
                Score = ScoreOfferUrl(sourceText, url, index, urls.Count),
                Index = index
            })
            .OrderByDescending(x => x.Score)
            .ThenByDescending(x => x.Index)
            .ToList();

        var best = scored.First();
        if (IsCouponLikeSelection(sourceText, best.Url) && scored.Count > 1)
        {
            var bestNonCoupon = scored.FirstOrDefault(x => !IsCouponLikeSelection(sourceText, x.Url));
            if (bestNonCoupon is not null)
            {
                return (bestNonCoupon.Url, $"URL principal ajustada por heuristica anti-cupom (score {bestNonCoupon.Score}).", Math.Min(78, Math.Max(42, bestNonCoupon.Score)));
            }
        }

        return (best.Url, $"URL principal selecionada por heuristica contextual (score {best.Score}).", Math.Min(72, Math.Max(35, best.Score)));
    }

    private async Task<(string? Url, string Reason)> SelectPrimaryOfferUrlWithAiAsync(
        string sourceText,
        IReadOnlyList<string> urls,
        AutomationSettings settings,
        CancellationToken cancellationToken)
    {
        var instagramSettings = settings.InstagramPosts ?? new InstagramPostSettings();
        if (!instagramSettings.UseAi || urls.Count <= 1)
        {
            return (null, string.Empty);
        }

        var provider = string.IsNullOrWhiteSpace(instagramSettings.AiProvider)
            ? "openai"
            : instagramSettings.AiProvider.Trim().ToLowerInvariant();

        var prompt = $$"""
        Voce esta analisando uma mensagem de oferta com mais de um link.
        Sua tarefa e escolher APENAS a URL que mais provavelmente aponta para o produto principal.
        Nao escolha link de cupom, resgate, landing, instrucoes ou pagina de campanha.
        Responda APENAS JSON valido:

        {
          "primaryOfferUrl": "uma das URLs da lista ou vazio",
          "reasoning": "explicacao curta em portugues"
        }

        Texto:
        {{sourceText}}

        URLs candidatas:
        {{string.Join("\n", urls.Select((url, index) => $"{index + 1}. {url}"))}}

        Regras:
        - prefira link associado ao nome do produto e preco
        - penalize link perto de palavras como cupom, resgate, pegue, desbloqueie
        - se houver duvida, prefira a URL que parece ser do item final e nao da promocao
        """;

        var raw = await GenerateAiTextAsync(prompt, provider, settings, cancellationToken);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return (null, string.Empty);
        }

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            var selected = root.TryGetProperty("primaryOfferUrl", out var urlNode) && urlNode.ValueKind == JsonValueKind.String
                ? urlNode.GetString()?.Trim()
                : null;
            var reasoning = root.TryGetProperty("reasoning", out var reasonNode) && reasonNode.ValueKind == JsonValueKind.String
                ? reasonNode.GetString()?.Trim()
                : null;

            if (string.IsNullOrWhiteSpace(selected))
            {
                return (null, string.Empty);
            }

            var matched = urls.FirstOrDefault(x => string.Equals(x, selected, StringComparison.OrdinalIgnoreCase));
            if (string.IsNullOrWhiteSpace(matched))
            {
                return (null, string.Empty);
            }

            return (matched, $"URL principal selecionada por IA ({provider}). {reasoning}");
        }
        catch
        {
            return (null, string.Empty);
        }
    }

    private async Task<string?> GenerateAiTextAsync(string prompt, string provider, AutomationSettings settings, CancellationToken cancellationToken)
    {
        return provider switch
        {
            "gemini" => await _geminiGenerator.GenerateFreeformAsync(prompt, settings.Gemini ?? new GeminiSettings(), cancellationToken),
            "deepseek" => await _deepSeekGenerator.GenerateFreeformAsync(prompt, settings.DeepSeek ?? new DeepSeekSettings(), cancellationToken),
            "nemotron" => await _nemotronGenerator.GenerateFreeformAsync(prompt, settings.Nemotron ?? new NemotronSettings(), cancellationToken),
            "qwen" => await _qwenGenerator.GenerateFreeformAsync(prompt, settings.Qwen ?? new QwenSettings(), cancellationToken),
            "vila" => await _vilaGenerator.GenerateFreeformAsync(prompt, settings.VilaNvidia ?? new VilaNvidiaSettings(), cancellationToken),
            _ => await _openAiGenerator.GenerateFreeformAsync(prompt, settings.OpenAI ?? new OpenAISettings(), cancellationToken)
        };
    }

    private static int ScoreOfferUrl(string sourceText, string url, int index, int totalUrls)
    {
        var score = 10 + index * 5;
        var normalizedText = sourceText ?? string.Empty;
        var urlIndex = normalizedText.IndexOf(url, StringComparison.OrdinalIgnoreCase);
        var context = urlIndex >= 0
            ? normalizedText.Substring(Math.Max(0, urlIndex - 80), Math.Min(normalizedText.Length - Math.Max(0, urlIndex - 80), url.Length + 160))
            : normalizedText;
        var contextLower = context.ToLowerInvariant();

        if (contextLower.Contains("cupom") || contextLower.Contains("resgate"))
        {
            score -= 18;
        }

        if (contextLower.Contains("r$") || contextLower.Contains("por ") || contextLower.Contains("preto") || contextLower.Contains("brastemp"))
        {
            score += 10;
        }

        if (index == totalUrls - 1)
        {
            score += 12;
        }

        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var path = uri.AbsolutePath.ToLowerInvariant();
            if (path.Contains("product") || path.Contains("item"))
            {
                score += 8;
            }
        }

        return score;
    }

    private static (string? Url, string Reason) OverrideCouponLikeSelection(
        string sourceText,
        IReadOnlyList<string> urls,
        string selectedUrl,
        string reasonIfOverridden)
    {
        if (!IsCouponLikeSelection(sourceText, selectedUrl))
        {
            return (null, string.Empty);
        }

        var replacement = urls
            .Where(url => !string.Equals(url, selectedUrl, StringComparison.OrdinalIgnoreCase))
            .Select((url, index) => new
            {
                Url = url,
                Score = ScoreOfferUrl(sourceText, url, index, urls.Count)
            })
            .Where(x => !IsCouponLikeSelection(sourceText, x.Url))
            .OrderByDescending(x => x.Score)
            .FirstOrDefault();

        return replacement is null ? (null, string.Empty) : (replacement.Url, reasonIfOverridden);
    }

    private static bool IsCouponLikeSelection(string sourceText, string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return false;
        }

        var normalizedText = sourceText ?? string.Empty;
        var urlIndex = normalizedText.IndexOf(url, StringComparison.OrdinalIgnoreCase);
        var context = urlIndex >= 0
            ? normalizedText.Substring(Math.Max(0, urlIndex - 100), Math.Min(normalizedText.Length - Math.Max(0, urlIndex - 100), url.Length + 200))
            : normalizedText;
        var lower = context.ToLowerInvariant();

        return lower.Contains("cupom") ||
               lower.Contains("resgate") ||
               lower.Contains("pegue o cupom") ||
               lower.Contains("pagina") ||
               lower.Contains("todos os cupons") ||
               lower.Contains("cupom de") ||
               lower.Contains("off aqui");
    }

    private static string NormalizeSourceChannel(string? sourceChannel)
        => string.Equals(sourceChannel, "whatsapp", StringComparison.OrdinalIgnoreCase) ? "whatsapp" : "telegram";

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));

    private static void AddDistinct(List<string> values, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (!values.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            values.Add(value.Trim());
        }
    }

    private static void AddIfUseful(List<string> values, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var normalized = value.Trim();
        if (normalized.Length < 24)
        {
            return;
        }

        AddDistinct(values, normalized);
    }

    private static bool DataLooksWeak(OfficialProductDataResult? official, LinkMetaResult meta)
    {
        var evidence = 0;
        if (!string.IsNullOrWhiteSpace(official?.Title) || !string.IsNullOrWhiteSpace(meta.Title)) evidence += 1;
        if (!string.IsNullOrWhiteSpace(official?.CurrentPrice) || !string.IsNullOrWhiteSpace(meta.PriceText)) evidence += 1;
        if ((official?.Images?.Count ?? 0) > 0 || meta.Images.Count > 0) evidence += 1;
        return evidence < 2;
    }

    private static bool IsBetterOfficialCandidate(OfficialProductDataResult? candidate, OfficialProductDataResult? current)
        => ScoreOfficialData(candidate) > ScoreOfficialData(current);

    private static bool IsBetterMetaCandidate(LinkMetaResult candidate, LinkMetaResult current)
        => ScoreMetaData(candidate) > ScoreMetaData(current);

    private static int ScoreOfficialData(OfficialProductDataResult? item)
    {
        if (item is null)
        {
            return 0;
        }

        var score = 0;
        if (!string.IsNullOrWhiteSpace(item.Title)) score += 25;
        if (!string.IsNullOrWhiteSpace(item.CurrentPrice)) score += 25;
        if (item.Images.Count > 0) score += 20;
        if (!string.IsNullOrWhiteSpace(item.EstimatedDelivery)) score += 10;
        if (item.IsOfficial) score += 10;
        if (item.DiscountPercent > 0) score += 10;
        return score;
    }

    private static int ScoreMetaData(LinkMetaResult item)
    {
        var score = 0;
        if (!string.IsNullOrWhiteSpace(item.Title)) score += 20;
        if (!string.IsNullOrWhiteSpace(item.PriceText)) score += 20;
        if (item.Images.Count > 0) score += 20;
        if (item.Videos.Count > 0) score += 10;
        if (!string.IsNullOrWhiteSpace(item.ResolvedUrl)) score += 10;
        if (item.DiscountPercentFromHtml > 0) score += 10;
        return score;
    }

    private sealed record DataEnrichmentResult(
        OfficialProductDataResult? Official,
        LinkMetaResult Meta,
        IReadOnlyList<string> AttemptedUrls,
        IReadOnlyList<string> FallbacksUsed,
        bool ScraperFallbackApplied);
}
