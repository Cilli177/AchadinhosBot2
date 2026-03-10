using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Http.Headers;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.ProductData;
using AchadinhosBot.Next.Infrastructure.Telegram;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramAutoPilotService : IInstagramAutoPilotService
{
    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private readonly ISettingsStore _settingsStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConversionLogStore _conversionLogStore;
    private readonly IClickLogStore _clickLogStore;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IInstagramPostComposer _instagramComposer;
    private readonly InstagramLinkMetaService _instagramMeta;
    private readonly OfficialProductDataService _officialProductDataService;
    private readonly IMediaStore _mediaStore;
    private readonly ICouponSelector _couponSelector;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly TelegramAlertSender _telegramAlertSender;
    private readonly WebhookOptions _webhookOptions;
    private readonly TelegramOptions _telegramOptions;
    private readonly EvolutionOptions _evolutionOptions;
    private readonly ILogger<InstagramAutoPilotService> _logger;

    public InstagramAutoPilotService(
        ISettingsStore settingsStore,
        IHttpClientFactory httpClientFactory,
        IConversionLogStore conversionLogStore,
        IClickLogStore clickLogStore,
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        IInstagramPostComposer instagramComposer,
        InstagramLinkMetaService instagramMeta,
        OfficialProductDataService officialProductDataService,
        IMediaStore mediaStore,
        ICouponSelector couponSelector,
        IWhatsAppGateway whatsAppGateway,
        TelegramAlertSender telegramAlertSender,
        IOptions<WebhookOptions> webhookOptions,
        IOptions<TelegramOptions> telegramOptions,
        IOptions<EvolutionOptions> evolutionOptions,
        ILogger<InstagramAutoPilotService> logger)
    {
        _settingsStore = settingsStore;
        _httpClientFactory = httpClientFactory;
        _conversionLogStore = conversionLogStore;
        _clickLogStore = clickLogStore;
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _instagramComposer = instagramComposer;
        _instagramMeta = instagramMeta;
        _officialProductDataService = officialProductDataService;
        _mediaStore = mediaStore;
        _couponSelector = couponSelector;
        _whatsAppGateway = whatsAppGateway;
        _telegramAlertSender = telegramAlertSender;
        _webhookOptions = webhookOptions.Value;
        _telegramOptions = telegramOptions.Value;
        _evolutionOptions = evolutionOptions.Value;
        _logger = logger;
    }

    public async Task<InstagramAutoPilotRunResult> RunNowAsync(InstagramAutoPilotRunRequest? request, CancellationToken cancellationToken)
    {
        var result = new InstagramAutoPilotRunResult();
        request ??= new InstagramAutoPilotRunRequest();
        var normalizedPostType = NormalizeAutoPilotPostType(request.PostType);
        var storyMode = string.Equals(normalizedPostType, "story", StringComparison.OrdinalIgnoreCase);
        result.PostType = normalizedPostType;

        try
        {
            var settings = await _settingsStore.GetAsync(cancellationToken);
            var instaPostSettings = settings.InstagramPosts ?? new InstagramPostSettings();
            var instaPublishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
            var geminiSettings = settings.Gemini ?? new GeminiSettings();

            var topCount = Math.Clamp(
                request.TopCount ?? (storyMode ? instaPublishSettings.StoryAutoPilotTopCount : instaPublishSettings.AutoPilotTopCount),
                1,
                10);
            var lookbackHours = Math.Clamp(
                request.LookbackHours ?? (storyMode ? instaPublishSettings.StoryAutoPilotLookbackHours : instaPublishSettings.AutoPilotLookbackHours),
                6,
                168);
            var repeatWindowHours = Math.Clamp(
                request.RepeatWindowHours ?? (storyMode ? instaPublishSettings.StoryAutoPilotRepeatWindowHours : instaPublishSettings.AutoPilotRepeatWindowHours),
                6,
                240);
            var sendForApproval = request.SendForApproval ?? (storyMode ? instaPublishSettings.StoryAutoPilotSendForApproval : instaPublishSettings.AutoPilotSendForApproval);
            var dryRun = request.DryRun;
            var manualUrl = request.ManualUrl?.Trim();
            var recentDraftKeys = request.ForceIncludeExisting
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                : await LoadRecentDraftKeysAsync(DateTimeOffset.UtcNow.AddHours(-repeatWindowHours), cancellationToken);

            List<CandidateScore> ranked;
            if (!string.IsNullOrWhiteSpace(manualUrl))
            {
                var manualKey = NormalizeUrlKey(manualUrl);
                if (recentDraftKeys.Contains(manualKey))
                {
                    await AppendAutoPilotSkipLogAsync(new CandidateScore
                    {
                        Url = manualUrl,
                        Key = manualKey,
                        Store = "Manual",
                        FinalScore = 100,
                        LatestTimestamp = DateTimeOffset.UtcNow,
                        Note = "Manual duplicate blocked"
                    }, "manual_duplicate_recent_draft", cancellationToken);

                    result.Success = true;
                    result.Message = $"URL ja possui draft recente dentro da janela de {repeatWindowHours}h. Use force se quiser repetir.";
                    return result;
                }

                _logger.LogInformation("Autopilot running in manual mode for URL: {Url}", manualUrl);
                ranked = new List<CandidateScore>
                {
                    new CandidateScore
                    {
                        Url = manualUrl,
                        Key = NormalizeUrlKey(manualUrl),
                        Store = "Manual",
                        ProductName = "Processando...", // Garantir que não seja filtrado
                        FinalScore = 100,
                        LatestTimestamp = DateTimeOffset.UtcNow,
                        Note = "Manual input"
                    }
                };
            }
            else
            {
                ranked = await BuildRankedCandidatesAsync(settings, instaPublishSettings, topCount, lookbackHours, repeatWindowHours, request.ForceIncludeExisting, cancellationToken);
            }

            result.CandidatesEvaluated = ranked.Count;

            var selected = ranked
                .Where(x => !string.IsNullOrWhiteSpace(x.ProductName))
                .OrderByDescending(x => x.FinalScore)
                .ThenByDescending(x => x.EngagementSignal)
                .ThenByDescending(x => x.LatestTimestamp)
                .Take(topCount)
                .ToList();
            result.SelectedCount = selected.Count;

            foreach (var candidate in selected)
            {
                candidate.Url = await ExpandCandidateUrlAsync(candidate.Url, cancellationToken);
                candidate.ProductName = TryResolveRealProductName(null, candidate.ProductName, candidate.Url, candidate.Store);

                var item = new InstagramAutoPilotSelectionItem
                {
                    ProductUrl = candidate.Url,
                    Store = candidate.Store,
                    ProductName = candidate.ProductName,
                    ProductDataSource = candidate.DataSource,
                    ImageUrl = candidate.SelectedImageUrl,
                    ImageMatchScore = candidate.ImageMatchScore,
                    ImageMatchReason = candidate.ImageMatchReason,
                    SalesSignal = candidate.SalesSignal,
                    ReturnSignal = candidate.ReturnSignal,
                    DiscountSignal = candidate.DiscountSignal,
                    RecencySignal = candidate.RecencySignal,
                    EngagementSignal = candidate.EngagementSignal,
                    FinalScore = candidate.FinalScore,
                    Note = candidate.Note
                };
                result.Selected.Add(item);
            }

            if (!dryRun)
            {
                // Cria em ordem reversa para que o item 1 da aprovacao fique como draft mais recente
                // e funcione com o atalho /ig revisar 1.
                foreach (var candidate in selected.AsEnumerable().Reverse())
                {
                    var draft = await CreateDraftFromCandidateAsync(candidate, instaPostSettings, instaPublishSettings, geminiSettings, normalizedPostType, cancellationToken);
                    if (draft is null)
                    {
                        continue;
                    }

                    result.DraftsCreated++;
                    var selectedItem = result.Selected.FirstOrDefault(x => string.Equals(x.ProductUrl, candidate.Url, StringComparison.OrdinalIgnoreCase));
                    if (selectedItem is not null)
                    {
                        selectedItem.DraftId = draft.Id;
                        selectedItem.ProductDataSource = candidate.DataSource;
                        selectedItem.ImageUrl = candidate.SelectedImageUrl;
                        selectedItem.ImageMatchScore = candidate.ImageMatchScore;
                        selectedItem.ImageMatchReason = candidate.ImageMatchReason;
                    }
                }
            }

            var approvalChannel = ResolveApprovalChannel(request, instaPublishSettings, storyMode);
            result.ApprovalChannel = approvalChannel;
            if (!dryRun && sendForApproval && result.DraftsCreated > 0)
            {
                var (sent, target) = await SendApprovalAsync(
                    result.Selected.Where(x => !string.IsNullOrWhiteSpace(x.DraftId)).ToList(),
                    request,
                    settings,
                    instaPublishSettings,
                    approvalChannel,
                    storyMode,
                    normalizedPostType,
                    cancellationToken);
                result.ApprovalSent = sent;
                result.ApprovalTarget = target;
            }

            result.Success = true;
            result.Message = BuildSummaryMessage(result, dryRun, sendForApproval, normalizedPostType);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Instagram autopilot failed.");
            result.Success = false;
            result.Message = $"Erro no autopilot: {ex.Message}";
        }

        return result;
    }

    private async Task<List<CandidateScore>> BuildRankedCandidatesAsync(
        AutomationSettings settings,
        InstagramPublishSettings instaPublishSettings,
        int topCount,
        int lookbackHours,
        int repeatWindowHours,
        bool forceIncludeExisting,
        CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var minTimestamp = now.AddHours(-lookbackHours);
        var existingKeys = forceIncludeExisting
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : await LoadRecentDraftKeysAsync(now.AddHours(-repeatWindowHours), ct);

        var conversionLogs = await _conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 500 }, ct);
        var clickLogs = await _clickLogStore.QueryAsync(null, 500, ct);

        var clickMap = clickLogs
            .Where(x => !string.IsNullOrWhiteSpace(x.TargetUrl))
            .GroupBy(x => NormalizeUrlKey(x.TargetUrl))
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var discountCache = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var candidates = conversionLogs
            .Where(x => x.Success && x.IsAffiliated && x.Timestamp >= minTimestamp)
            .Select(x => new
            {
                Entry = x,
                RankingUrl = ResolveRankingUrl(x)
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.RankingUrl))
            .GroupBy(x => NormalizeUrlKey(x.RankingUrl))
            .Select(g => new
            {
                Key = g.Key,
                Entries = g.OrderByDescending(e => e.Entry.Timestamp).ToList()
            })
            .Where(g => !string.IsNullOrWhiteSpace(g.Key))
            .ToList();

        var list = new List<CandidateScore>();
        foreach (var group in candidates)
        {
            var latest = group.Entries[0].Entry;
            var store = string.IsNullOrWhiteSpace(latest.Store) ? "Unknown" : latest.Store.Trim();
            var clickSignal = group.Entries.Sum(x => Math.Max(0, x.Entry.Clicks));
            if (clickMap.TryGetValue(group.Key, out var trackedClicks))
            {
                clickSignal += trackedClicks;
            }

            var conversionsSignal = group.Entries.Count;
            var salesSignal = Math.Min(60, conversionsSignal * 8 + clickSignal * 2);
            var returnSignal = Math.Min(25, GetStoreReturnSignal(store) + (int)Math.Round(group.Entries.Count(x => x.Entry.IsAffiliated) * 8d / Math.Max(1, group.Entries.Count)));
            var discountSignal = await GetDiscountSignalAsync(settings, store, discountCache, ct);
            var recencySignal = ComputeRecencySignal(now, latest.Timestamp);
            var finalScore = ComputeWeightedScore(
                salesSignal,
                returnSignal,
                discountSignal,
                recencySignal,
                instaPublishSettings);

            var url = ResolveRankingUrl(latest);
            if (!instaPublishSettings.AutoPilotAllowShortLinks && IsLikelyShortLink(url))
            {
                continue;
            }

            var key = NormalizeUrlKey(url);
            if (existingKeys.Contains(key))
            {
                _logger.LogDebug("Skipping candidate already in recent drafts: {Url}", url);
                continue;
            }

            list.Add(new CandidateScore
            {
                Key = key,
                Url = url,
                Store = store,
                SalesSignal = salesSignal,
                ReturnSignal = returnSignal,
                DiscountSignal = discountSignal,
                RecencySignal = recencySignal,
                FinalScore = finalScore,
                LatestTimestamp = latest.Timestamp,
                Note = $"conversions={conversionsSignal}, clicks={clickSignal}, weights={instaPublishSettings.AutoPilotWeightSales}/{instaPublishSettings.AutoPilotWeightReturn}/{instaPublishSettings.AutoPilotWeightDiscount}/{instaPublishSettings.AutoPilotWeightRecency}"
            });
        }

        await EnrichCandidatesForInstagramAsync(list, topCount, ct);
        return list;
    }

    private async Task EnrichCandidatesForInstagramAsync(List<CandidateScore> candidates, int topCount, CancellationToken ct)
    {
        if (candidates.Count == 0)
        {
            return;
        }

        var poolSize = Math.Clamp(Math.Max(topCount * 5, 12), 12, 40);
        var shortlist = candidates
            .OrderByDescending(x => x.FinalScore)
            .ThenByDescending(x => x.LatestTimestamp)
            .Take(poolSize)
            .ToList();

        foreach (var candidate in shortlist)
        {
            ct.ThrowIfCancellationRequested();
            candidate.Url = await ExpandCandidateUrlAsync(candidate.Url, ct);

            LinkMetaResult meta;
            try
            {
                meta = await _instagramMeta.GetMetaAsync(candidate.Url, ct);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not load metadata for candidate {Url}", candidate.Url);
                meta = new LinkMetaResult();
            }

            var productName = TryResolveRealProductName(meta.Title, candidate.ProductName, candidate.Url, candidate.Store);
            candidate.ProductName = productName;

            var engagement = ComputeInstagramEngagementSignal(
                productName,
                candidate.Store,
                meta.Images.Count,
                candidate.SalesSignal,
                candidate.DiscountSignal,
                candidate.RecencySignal);

            if (string.IsNullOrWhiteSpace(productName))
            {
                engagement -= 12;
            }

            candidate.EngagementSignal = Math.Clamp(engagement, -20, 25);
            candidate.FinalScore = Math.Clamp(candidate.FinalScore + candidate.EngagementSignal, 0, 100);

            var titleFound = string.IsNullOrWhiteSpace(meta.Title) ? "no" : "yes";
            candidate.Note = $"{candidate.Note}, engagement={candidate.EngagementSignal}, title={titleFound}, images={meta.Images.Count}";
        }
    }

    private async Task<HashSet<string>> LoadRecentDraftKeysAsync(DateTimeOffset minTimestamp, CancellationToken ct)
    {
        var drafts = await _publishStore.ListAsync(ct);
        return drafts
            .Where(x => x.CreatedAt >= minTimestamp && !string.Equals(x.Status, "failed", StringComparison.OrdinalIgnoreCase))
            .SelectMany(x => x.Ctas ?? new List<InstagramCtaOption>())
            .Select(x => x.Link)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(NormalizeUrlKey)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private async Task<InstagramPublishDraft?> CreateDraftFromCandidateAsync(
        CandidateScore candidate,
        InstagramPostSettings settings,
        InstagramPublishSettings publishSettings,
        GeminiSettings geminiSettings,
        string postType,
        CancellationToken ct)
    {
        try
        {
            var requireOfficialData = publishSettings.AutoPilotRequireOfficialProductData;
            var requireAiCaption = publishSettings.AutoPilotRequireAiCaption;
            var minImageMatchScore = Math.Clamp(publishSettings.AutoPilotMinimumImageMatchScore, 0, 100);

            var candidateUrl = await ExpandCandidateUrlAsync(candidate.Url, ct);
            if (!string.IsNullOrWhiteSpace(candidateUrl))
            {
                candidate.Url = candidateUrl;
            }

            var officialData = await _officialProductDataService.TryGetBestAsync(candidate.Url, null, ct);
            candidate.DataSource = !string.IsNullOrWhiteSpace(officialData?.DataSource) ? officialData!.DataSource : "meta";
            if (requireOfficialData && officialData is null)
            {
                _logger.LogInformation("Skipping autopilot candidate without official product data: {Url}", candidate.Url);
                await AppendAutoPilotSkipLogAsync(candidate, "missing_official_data", ct);
                return null;
            }

            var offerContext = $"Score {candidate.FinalScore} | vendas={candidate.SalesSignal} retorno={candidate.ReturnSignal} desconto={candidate.DiscountSignal}";
            settings.UseAi = true;
            var postText = await _instagramComposer.BuildAsync(candidate.Url, offerContext, settings, ct);
            var aiFailed = postText.StartsWith("Nao consegui gerar legenda com IA", StringComparison.OrdinalIgnoreCase);
            if (aiFailed && requireAiCaption)
            {
                _logger.LogInformation("Skipping autopilot candidate because AI caption is required and generation failed: {Url}", candidate.Url);
                await AppendAutoPilotSkipLogAsync(candidate, "ai_caption_failed", ct);
                return null;
            }

            var (captionsRaw, hashtagsRaw) = ExtractCaptionsAndHashtags(postText);

            var meta = await _instagramMeta.GetMetaAsync(candidate.Url, ct);
            var productName = TryResolveRealProductName(officialData?.Title, meta.Title, candidate.Url, candidate.Store);
            if (string.IsNullOrWhiteSpace(productName))
            {
                productName = TryResolveRealProductName(meta.Title, candidate.ProductName, candidate.Url, candidate.Store);
            }
            if (string.IsNullOrWhiteSpace(productName))
            {
                _logger.LogInformation("Skipping autopilot candidate without reliable product title: {Url}", candidate.Url);
                await AppendAutoPilotSkipLogAsync(candidate, "missing_product_title", ct);
                return null;
            }

            candidate.ProductName = productName;
            var link = ExtractFirstUrl(postText) ?? candidate.Url;
            var keyword = BuildKeyword(productName, candidate.Store);

            var captions = new List<string>();
            if (!aiFailed)
            {
                captions = captionsRaw
                    .Select(FormatCaption)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => EnsureCaptionContainsCta(x, keyword))
                    .Select(x => x.Length > 2200 ? x[..2200].TrimEnd() + "..." : x)
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
                if (captions.Count == 0)
                {
                    captions.Add(EnsureCaptionContainsCta(FormatCaption(postText), keyword));
                }
            }

            if (captions.Count == 0)
            {
                captions.Add(BuildAutoPilotFallbackCaption(productName, keyword, candidate.Store, postType));
            }

            if (aiFailed)
            {
                _logger.LogInformation("Autopilot using fallback caption because AI generation failed: {Url}", candidate.Url);
            }

            var hashtags = NormalizeHashtags(hashtagsRaw, candidate.Store, productName);
            var imagesRaw = NormalizeExternalUrls(
                (officialData?.Images ?? new List<string>())
                    .Concat(meta.Images ?? new List<string>())
                    .ToList(),
                10);
            var imageSelection = await SelectBestImagesForProductAsync(productName, candidate.Store, imagesRaw, geminiSettings, ct);
            if (minImageMatchScore > 0 &&
                imageSelection.BestScore.HasValue &&
                imageSelection.BestScore.Value < minImageMatchScore)
            {
                _logger.LogInformation(
                    "Skipping autopilot candidate due to low image match score ({Score}/{Min}): {Url}",
                    imageSelection.BestScore.Value,
                    minImageMatchScore,
                    candidate.Url);
                candidate.ImageMatchScore = imageSelection.BestScore;
                candidate.ImageMatchReason = imageSelection.BestReason;
                await AppendAutoPilotSkipLogAsync(candidate, $"low_image_match:{imageSelection.BestScore.Value}/{minImageMatchScore}", ct);
                return null;
            }
            var images = await HostImagesAsJpegAsync(imageSelection.OrderedUrls, ct);
            if (images.Count == 0)
            {
                images = imageSelection.OrderedUrls
                    .Where(x => !IsLikelyWebpImageUrl(x))
                    .ToList();
            }

            if (images.Count == 0)
            {
                images = imageSelection.OrderedUrls;
            }

            candidate.SelectedImageUrl = images.FirstOrDefault() ?? imageSelection.BestImageUrl;
            candidate.ImageMatchScore = imageSelection.BestScore;
            candidate.ImageMatchReason = imageSelection.BestReason;
            var ctas = new List<InstagramCtaOption>
            {
                new()
                {
                    Keyword = keyword,
                    Link = link
                }
            };

            var draft = new InstagramPublishDraft
            {
                PostType = postType,
                ProductName = productName,
                Caption = captions[0],
                CaptionOptions = captions,
                SelectedCaptionIndex = 1,
                Hashtags = hashtags,
                ImageUrls = images,
                Ctas = ctas,
                Status = "draft"
            };

            await _publishStore.SaveAsync(draft, ct);
            await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "autopilot_draft_created",
                Success = true,
                DraftId = draft.Id,
                Details = $"Score={candidate.FinalScore};Store={candidate.Store};Url={candidate.Url};Image={candidate.SelectedImageUrl};ImageMatch={candidate.ImageMatchScore};DataSource={candidate.DataSource}"
            }, ct);

            return draft;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create draft for candidate {Url}", candidate.Url);
            await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "autopilot_draft_created",
                Success = false,
                Error = ex.Message,
                Details = candidate.Url
            }, ct);
            return null;
        }
    }

    private async Task<(bool Sent, string? Target)> SendApprovalAsync(
        IReadOnlyList<InstagramAutoPilotSelectionItem> selected,
        InstagramAutoPilotRunRequest request,
        AutomationSettings rootSettings,
        InstagramPublishSettings settings,
        string channel,
        bool storyMode,
        string postType,
        CancellationToken ct)
    {
        if (selected.Count == 0)
        {
            return (false, null);
        }

        var message = BuildApprovalMessage(selected, postType);
        if (string.Equals(channel, "whatsapp", StringComparison.OrdinalIgnoreCase))
        {
            var groupId = FirstNotEmpty(
                request.ApprovalWhatsAppGroupId,
                storyMode ? settings.StoryAutoPilotApprovalWhatsAppGroupId : settings.AutoPilotApprovalWhatsAppGroupId);
            if (string.IsNullOrWhiteSpace(groupId))
            {
                return (false, null);
            }

            var instanceName = FirstNotEmpty(
                request.ApprovalWhatsAppInstanceName,
                storyMode ? settings.StoryAutoPilotApprovalWhatsAppInstanceName : settings.AutoPilotApprovalWhatsAppInstanceName,
                _evolutionOptions.InstanceName);
            var send = await _whatsAppGateway.SendTextAsync(instanceName, groupId, message, ct);
            return (send.Success, groupId);
        }

        var forwardingChatId = rootSettings.TelegramForwarding?.DestinationChatId ?? 0;
        var chatId = request.ApprovalTelegramChatId
            ?? ((storyMode ? settings.StoryAutoPilotApprovalTelegramChatId : settings.AutoPilotApprovalTelegramChatId) != 0
                ? (storyMode ? settings.StoryAutoPilotApprovalTelegramChatId : settings.AutoPilotApprovalTelegramChatId)
                : settings.AutoPilotApprovalTelegramChatId != 0
                    ? settings.AutoPilotApprovalTelegramChatId
                    : forwardingChatId != 0
                        ? forwardingChatId
                        : _telegramOptions.LogsChatId);
        if (chatId == 0)
        {
            return (false, null);
        }

        var sent = await _telegramAlertSender.SendAsync(chatId, message, ct);
        return (sent, chatId.ToString());
    }

    private async Task SendDraftApprovalAsync(InstagramPublishDraft draft, InstagramPublishSettings settings, CancellationToken ct)
    {
        var chatId = draft.PostType == "story" 
            ? settings.StoryAutoPilotApprovalTelegramChatId 
            : settings.AutoPilotApprovalTelegramChatId;

        if (chatId == 0) return;

        var sb = new StringBuilder();
        sb.AppendLine($"🚀 **{draft.PostType.ToUpper()} AUTOPILOT**");
        sb.AppendLine($"Produto: {draft.ProductName}");
        sb.AppendLine($"Draft ID: `{draft.Id}`");
        sb.AppendLine();
        sb.AppendLine("Ações rápidas disponíveis nos botões abaixo:");

        var inlineKeyboard = new
        {
            inline_keyboard = new[]
            {
                new[]
                {
                    new { text = "✅ Confirmar", callback_data = $"ig:approve:{draft.Id}" },
                    new { text = "📝 Revisar", callback_data = $"ig:review:{draft.Id}" },
                    new { text = "🗑️ Ignorar", callback_data = $"ig:ignore:{draft.Id}" }
                }
            }
        };

        await _telegramAlertSender.SendAsync(chatId, sb.ToString(), inlineKeyboard, ct);
    }

    private async Task AppendAutoPilotSkipLogAsync(CandidateScore candidate, string reason, CancellationToken ct)
    {
        await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "autopilot_candidate_skipped",
            Success = true,
            Details = $"Reason={reason};Score={candidate.FinalScore};Store={candidate.Store};Url={candidate.Url};DataSource={candidate.DataSource};ImageMatch={candidate.ImageMatchScore}"
        }, ct);
    }

    private static string BuildApprovalMessage(IReadOnlyList<InstagramAutoPilotSelectionItem> selected, string postType)
    {
        var sb = new StringBuilder();
        var label = string.Equals(postType, "story", StringComparison.OrdinalIgnoreCase) ? "STORY" : "FEED";
        sb.AppendLine($"AUTOPILOT INSTAGRAM {label}");
        sb.AppendLine("Rascunhos criados para aprovacao:");
        sb.AppendLine();

        for (var i = 0; i < selected.Count; i++)
        {
            var item = selected[i];
            var shortDraft = item.DraftId is { Length: > 8 } ? item.DraftId[..8] : item.DraftId;
            sb.AppendLine($"{i + 1}) Produto: {FirstNotEmpty(item.ProductName, item.Store)}");
            sb.AppendLine($"Loja: {item.Store} | Score: {item.FinalScore} | Engajamento: {item.EngagementSignal}");
            if (!string.IsNullOrWhiteSpace(item.ProductDataSource))
            {
                sb.AppendLine($"Fonte de dados: {item.ProductDataSource}");
            }
            sb.AppendLine($"Draft: {shortDraft}");
            if (!string.IsNullOrWhiteSpace(item.ImageUrl))
            {
                var match = item.ImageMatchScore.HasValue ? item.ImageMatchScore.Value.ToString() : "n/a";
                sb.AppendLine($"Foto sugerida: {item.ImageUrl}");
                sb.AppendLine($"Match imagem/produto: {match}/100");
                if (!string.IsNullOrWhiteSpace(item.ImageMatchReason))
                {
                    sb.AppendLine($"Motivo match: {item.ImageMatchReason}");
                }
            }
            sb.AppendLine($"Comandos: /ig revisar {shortDraft} | /ig confirmar {shortDraft}");
            sb.AppendLine($"Atalho desta rodada: /ig revisar {i + 1} | /ig confirmar {i + 1}");
            sb.AppendLine();
        }

        sb.AppendLine("Valide o texto/imagens e confirme apenas os que fizerem sentido.");
        return sb.ToString().Trim();
    }

    private static string BuildSummaryMessage(InstagramAutoPilotRunResult result, bool dryRun, bool sendForApproval, string postType)
    {
        if (!result.Success)
        {
            return result.Message;
        }

        var mode = dryRun ? "dry-run" : "execucao";
        var approval = sendForApproval ? (result.ApprovalSent ? "aprovacao enviada" : "aprovacao pendente") : "sem envio para aprovacao";
        return $"Autopilot {postType} {mode} concluido: candidatos={result.CandidatesEvaluated}, selecionados={result.SelectedCount}, drafts={result.DraftsCreated}, {approval}.";
    }

    private static int GetStoreReturnSignal(string store)
    {
        var normalized = store.Trim().ToLowerInvariant();
        return normalized switch
        {
            "mercado livre" => 16,
            "shopee" => 14,
            "amazon" => 13,
            "shein" => 12,
            _ => 8
        };
    }

    private async Task<int> GetDiscountSignalAsync(
        AutomationSettings settings,
        string store,
        Dictionary<string, int> cache,
        CancellationToken ct)
    {
        var normalized = _couponSelector.NormalizeStore(store);
        if (cache.TryGetValue(normalized, out var cached))
        {
            return cached;
        }

        var signal = 0;
        try
        {
            if (settings.CouponHub.Enabled)
            {
                var coupons = await _couponSelector.GetActiveCouponsAsync(store, 3, ct);
                if (coupons.Count > 0)
                {
                    signal += 8;
                    var parsedBest = coupons
                        .Select(c => ParseDiscountMagnitude(c.Description) + ParseDiscountMagnitude(c.Code))
                        .DefaultIfEmpty(0)
                        .Max();
                    signal += Math.Min(17, parsedBest);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not compute discount signal for store {Store}", store);
        }

        cache[normalized] = signal;
        return signal;
    }

    private static int ComputeRecencySignal(DateTimeOffset now, DateTimeOffset latest)
    {
        var hours = Math.Max(0, (now - latest).TotalHours);
        if (hours <= 1) return 20;
        if (hours <= 3) return 16;
        if (hours <= 6) return 12;
        if (hours <= 12) return 9;
        if (hours <= 24) return 6;
        return 3;
    }

    private static int ComputeWeightedScore(
        int salesSignal,
        int returnSignal,
        int discountSignal,
        int recencySignal,
        InstagramPublishSettings settings)
    {
        var wSales = ClampWeight(settings.AutoPilotWeightSales, 35);
        var wReturn = ClampWeight(settings.AutoPilotWeightReturn, 30);
        var wDiscount = ClampWeight(settings.AutoPilotWeightDiscount, 25);
        var wRecency = ClampWeight(settings.AutoPilotWeightRecency, 10);
        var weightTotal = wSales + wReturn + wDiscount + wRecency;
        if (weightTotal <= 0)
        {
            return salesSignal + returnSignal + discountSignal + recencySignal;
        }

        var weighted = (salesSignal * wSales)
                       + (returnSignal * wReturn)
                       + (discountSignal * wDiscount)
                       + (recencySignal * wRecency);
        return (int)Math.Round(weighted / (double)weightTotal);
    }

    private static int ComputeInstagramEngagementSignal(
        string? productName,
        string store,
        int imageCount,
        int salesSignal,
        int discountSignal,
        int recencySignal)
    {
        var score = 0;
        var normalizedName = (productName ?? string.Empty).Trim();

        if (!string.IsNullOrWhiteSpace(normalizedName) && !LooksOpaqueProductName(normalizedName) && !LooksGenericProductName(normalizedName))
        {
            score += 8;
        }

        if (imageCount > 0)
        {
            score += 5;
            if (imageCount >= 3)
            {
                score += 4;
            }
        }

        var lowerName = normalizedName.ToLowerInvariant();
        var keywordHits = InstagramEngagementTerms.Count(term => lowerName.Contains(term, StringComparison.OrdinalIgnoreCase));
        score += Math.Min(8, keywordHits * 2);

        if (salesSignal >= 30)
        {
            score += 4;
        }

        if (discountSignal >= 8)
        {
            score += 4;
        }

        if (recencySignal >= 12)
        {
            score += 2;
        }

        if (!string.IsNullOrWhiteSpace(store))
        {
            score += 1;
        }

        if (LooksGenericProductName(normalizedName))
        {
            score -= 8;
        }

        return score;
    }

    private static int ClampWeight(int input, int fallback)
    {
        var value = input <= 0 ? fallback : input;
        return Math.Clamp(value, 1, 100);
    }

    private static int ParseDiscountMagnitude(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return 0;
        }

        var normalized = text.Replace(',', '.');
        var percentage = Regex.Match(normalized, @"(\d{1,2}(?:\.\d+)?)\s*%", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (percentage.Success && double.TryParse(percentage.Groups[1].Value, out var pct))
        {
            return (int)Math.Min(15, Math.Round(pct / 5d));
        }

        var currency = Regex.Match(normalized, @"(?:r\$|\$)\s*(\d{1,4}(?:\.\d{1,2})?)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (currency.Success && double.TryParse(currency.Groups[1].Value, out var amount))
        {
            return (int)Math.Min(15, Math.Round(amount / 20d));
        }

        return 0;
    }

    private static string ResolveApprovalChannel(InstagramAutoPilotRunRequest request, InstagramPublishSettings settings, bool storyMode)
    {
        var storyChannel = storyMode ? settings.StoryAutoPilotApprovalChannel : null;
        if (storyMode &&
            string.Equals((storyChannel ?? string.Empty).Trim(), "whatsapp", StringComparison.OrdinalIgnoreCase) &&
            string.Equals((settings.AutoPilotApprovalChannel ?? string.Empty).Trim(), "telegram", StringComparison.OrdinalIgnoreCase))
        {
            storyChannel = settings.AutoPilotApprovalChannel;
        }

        var value = FirstNotEmpty(
            request.ApprovalChannel,
            storyChannel,
            settings.AutoPilotApprovalChannel,
            "telegram");
        return value.Trim().ToLowerInvariant() switch
        {
            "wa" => "whatsapp",
            "zap" => "whatsapp",
            "whatsapp" => "whatsapp",
            _ => "telegram"
        };
    }

    private static string BuildAutoPilotFallbackCaption(string productName, string keyword, string store, string postType)
    {
        var safeProduct = string.IsNullOrWhiteSpace(productName) ? "Oferta do dia" : productName.Trim();
        if (string.Equals(postType, "story", StringComparison.OrdinalIgnoreCase))
        {
            return $"ITEM: {safeProduct}\nLink na bio.\nComente \"{keyword}\" para receber o link.";
        }

        var safeStore = string.IsNullOrWhiteSpace(store) ? "loja parceira" : store.Trim();
        return $"{safeProduct} em destaque na {safeStore}.\nComente \"{keyword}\" para receber o link.";
    }

    private static string NormalizeAutoPilotPostType(string? input)
    {
        var normalized = (input ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "story" => "story",
            "stories" => "story",
            _ => "feed"
        };
    }

    private static string ResolveRankingUrl(ConversionLogEntry entry)
    {
        var converted = (entry.ConvertedUrl ?? string.Empty).Trim();
        var original = (entry.OriginalUrl ?? string.Empty).Trim();
        if (!string.IsNullOrWhiteSpace(converted) && !IsLikelyShortLink(converted))
        {
            return converted;
        }

        if (!string.IsNullOrWhiteSpace(original))
        {
            return original;
        }

        return converted;
    }

    private async Task<string> ExpandCandidateUrlAsync(string url, CancellationToken ct)
    {
        if (!IsLikelyShortLink(url))
        {
            return url;
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            var resolved = response.RequestMessage?.RequestUri?.ToString();
            if (!string.IsNullOrWhiteSpace(resolved))
            {
                return resolved;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not expand short candidate URL {Url}", url);
        }

        return url;
    }

    private static bool LooksOpaqueProductName(string name)
    {
        var value = (name ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        if (value.Contains(' '))
        {
            return false;
        }

        return Regex.IsMatch(value, @"^[A-Za-z0-9]{4,12}$", RegexOptions.CultureInvariant);
    }

    private static bool LooksGenericProductName(string? name)
    {
        var value = (name ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var normalized = Regex.Replace(value.ToLowerInvariant(), @"[^\p{L}\p{N}\s]", " ", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"\s+", " ", RegexOptions.CultureInvariant).Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return true;
        }

        if (GenericProductNameTerms.Contains(normalized))
        {
            return true;
        }

        if (normalized.StartsWith("oferta ", StringComparison.Ordinal) ||
            normalized.StartsWith("produto ", StringComparison.Ordinal))
        {
            return true;
        }

        var tokens = normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return tokens.Length == 1 && GenericProductNameTerms.Contains(tokens[0]);
    }

    private static string? TryResolveRealProductName(string? metaTitle, string? candidateName, string url, string store)
    {
        var options = new[]
        {
            NormalizeProductTitle(metaTitle, store),
            NormalizeProductTitle(candidateName, store),
            NormalizeProductTitle(TryExtractProductNameFromUrl(url), store)
        };

        return options
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!.Trim())
            .FirstOrDefault(x => !LooksOpaqueProductName(x) && !LooksGenericProductName(x));
    }

    private static string? NormalizeProductTitle(string? rawTitle, string store)
    {
        if (string.IsNullOrWhiteSpace(rawTitle))
        {
            return null;
        }

        var title = WebUtility.HtmlDecode(rawTitle)?.Trim() ?? string.Empty;
        title = title.Replace('\u00A0', ' ');
        title = Regex.Replace(title, @"\s+", " ", RegexOptions.CultureInvariant).Trim();
        if (title.Length < 6)
        {
            return null;
        }

        title = TrimMarketplaceSuffix(title, store);
        title = Regex.Replace(title, @"\s+", " ", RegexOptions.CultureInvariant).Trim(' ', '|', '-', '.', ':');
        if (title.Length < 6)
        {
            return null;
        }

        return title.Length > 110 ? title[..110].TrimEnd() : title;
    }

    private static string TrimMarketplaceSuffix(string title, string store)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return string.Empty;
        }

        var result = title.Trim();
        var normalizedStore = Regex.Replace((store ?? string.Empty).ToLowerInvariant(), @"\s+", string.Empty, RegexOptions.CultureInvariant);
        foreach (var sep in new[] { " | ", " - " })
        {
            var idx = result.LastIndexOf(sep, StringComparison.Ordinal);
            if (idx <= 0)
            {
                continue;
            }

            var suffix = result[(idx + sep.Length)..].Trim().ToLowerInvariant();
            var isMarketplaceSuffix = MarketplaceTitleTerms.Any(term => suffix.Contains(term, StringComparison.OrdinalIgnoreCase));
            if (!isMarketplaceSuffix && !string.IsNullOrWhiteSpace(normalizedStore))
            {
                isMarketplaceSuffix = suffix.Replace(" ", string.Empty, StringComparison.Ordinal).Contains(normalizedStore, StringComparison.OrdinalIgnoreCase);
            }

            if (isMarketplaceSuffix)
            {
                result = result[..idx].Trim();
            }
        }

        return result;
    }

    private static bool IsLikelyShortLink(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        return host is "tinyurl.com"
            or "bit.ly"
            or "t.co"
            or "cutt.ly"
            or "compre.link"
            or "oferta.one"
            or "s.shopee.com.br"
            or "shope.ee"
            or "meli.la"
            or "amzn.to"
            or "a.co";
    }

    private async Task<ImageSelectionResult> SelectBestImagesForProductAsync(
        string productName,
        string store,
        IReadOnlyList<string> imageUrls,
        GeminiSettings geminiSettings,
        CancellationToken ct)
    {
        var normalized = NormalizeExternalUrls(imageUrls, 10);
        if (normalized.Count == 0)
        {
            return new ImageSelectionResult(new List<string>(), null, null, null);
        }

        var useGemini = ShouldUseGeminiImageValidation(geminiSettings);
        var evaluations = new List<ImageCandidateEvaluation>();
        for (var i = 0; i < normalized.Count; i++)
        {
            var imageUrl = normalized[i];
            var heuristicScore = ComputeImageUrlRelevanceScore(productName, store, imageUrl);
            var finalScore = heuristicScore;
            var reason = $"heuristica_url={heuristicScore}";

            if (useGemini && i < 3)
            {
                var aiValidation = await EvaluateImageRelevanceWithGeminiAsync(productName, store, imageUrl, geminiSettings, ct);
                if (aiValidation is not null)
                {
                    finalScore = (int)Math.Round((aiValidation.Score * 0.7) + (heuristicScore * 0.3));
                    reason = aiValidation.Reason;
                }
            }

            evaluations.Add(new ImageCandidateEvaluation(imageUrl, finalScore, reason, i));
        }

        var ordered = evaluations
            .OrderByDescending(x => x.Score)
            .ThenBy(x => x.OriginalIndex)
            .ToList();
        var orderedUrls = ordered
            .Select(x => x.Url)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var best = ordered.FirstOrDefault();
        return new ImageSelectionResult(
            orderedUrls,
            best?.Url,
            best?.Score,
            best?.Reason);
    }

    private static bool ShouldUseGeminiImageValidation(GeminiSettings settings)
        => GetGeminiApiKeys(settings).Count > 0;

    private async Task<GeminiImageValidationResult?> EvaluateImageRelevanceWithGeminiAsync(
        string productName,
        string store,
        string imageUrl,
        GeminiSettings geminiSettings,
        CancellationToken ct)
    {
        try
        {
            var apiKeys = GetGeminiApiKeys(geminiSettings);
            if (apiKeys.Count == 0)
            {
                return null;
            }

            var client = _httpClientFactory.CreateClient("default");
            using var imageResponse = await client.GetAsync(imageUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!imageResponse.IsSuccessStatusCode)
            {
                return null;
            }

            var contentLength = imageResponse.Content.Headers.ContentLength;
            if (contentLength.HasValue && contentLength.Value > 5_000_000)
            {
                return null;
            }

            var imageBytes = await imageResponse.Content.ReadAsByteArrayAsync(ct);
            if (imageBytes.Length == 0 || imageBytes.Length > 5_000_000)
            {
                return null;
            }

            var mimeType = ResolveImageMimeType(imageResponse.Content.Headers.ContentType?.MediaType, imageUrl);
            if (!mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var prompt =
                "Avalie se esta imagem representa o produto informado. " +
                $"Produto: {productName}. Loja: {store}. " +
                "Responda somente JSON valido no formato: " +
                "{\"score\":0-100,\"isMatch\":true|false,\"reason\":\"texto curto\"}.";

            var payload = new Dictionary<string, object?>
            {
                ["contents"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["role"] = "user",
                        ["parts"] = new object[]
                        {
                            new Dictionary<string, object?> { ["text"] = prompt },
                            new Dictionary<string, object?>
                            {
                                ["inline_data"] = new Dictionary<string, object?>
                                {
                                    ["mime_type"] = mimeType,
                                    ["data"] = Convert.ToBase64String(imageBytes)
                                }
                            }
                        }
                    }
                },
                ["generationConfig"] = new Dictionary<string, object?>
                {
                    ["temperature"] = 0,
                    ["response_mime_type"] = "application/json"
                }
            };

            var model = string.IsNullOrWhiteSpace(geminiSettings.Model) ? "gemini-2.5-flash" : geminiSettings.Model.Trim();
            var baseUrl = string.IsNullOrWhiteSpace(geminiSettings.BaseUrl) ? "https://generativelanguage.googleapis.com/v1beta" : geminiSettings.BaseUrl.Trim();
            var geminiClient = _httpClientFactory.CreateClient("gemini");
            foreach (var apiKey in apiKeys)
            {
                var url = $"{baseUrl.TrimEnd('/')}/models/{model}:generateContent?key={Uri.EscapeDataString(apiKey)}";
                using var response = await geminiClient.PostAsync(
                    url,
                    new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
                    ct);

                var raw = await response.Content.ReadAsStringAsync(ct);
                if (!response.IsSuccessStatusCode)
                {
                    if (ShouldTryNextGeminiKey(response.StatusCode, raw))
                    {
                        continue;
                    }

                    return null;
                }

                var text = ExtractGeminiOutputText(raw);
                var parsed = ParseGeminiValidationResult(text);
                if (parsed is not null)
                {
                    return parsed;
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not validate image relevance with Gemini for {Url}", imageUrl);
            return null;
        }
    }

    private static List<string> GetGeminiApiKeys(GeminiSettings settings)
    {
        var keys = new List<string>();
        if (!string.IsNullOrWhiteSpace(settings.ApiKey) && settings.ApiKey != "********")
        {
            keys.Add(settings.ApiKey.Trim());
        }

        if (settings.ApiKeys is not null)
        {
            foreach (var key in settings.ApiKeys)
            {
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }

                var trimmed = key.Trim();
                if (trimmed == "********")
                {
                    continue;
                }

                keys.Add(trimmed);
            }
        }

        return keys
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private static bool ShouldTryNextGeminiKey(System.Net.HttpStatusCode statusCode, string? body)
    {
        var status = (int)statusCode;
        if (status is 401 or 403 or 429 or 500 or 502 or 503 or 504)
        {
            return true;
        }

        if (status == 400 && !string.IsNullOrWhiteSpace(body))
        {
            return body.Contains("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase) ||
                   body.Contains("quota", StringComparison.OrdinalIgnoreCase) ||
                   body.Contains("rate limit", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static GeminiImageValidationResult? ParseGeminiValidationResult(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var json = ExtractFirstJsonObject(text) ?? text.Trim();
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var score = root.TryGetProperty("score", out var scoreNode) && scoreNode.TryGetInt32(out var parsedScore)
                ? parsedScore
                : 0;
            score = Math.Clamp(score, 0, 100);

            var isMatch = root.TryGetProperty("isMatch", out var matchNode) && matchNode.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? matchNode.GetBoolean()
                : score >= 55;
            if (!isMatch && score > 60)
            {
                score = 60;
            }

            var reason = root.TryGetProperty("reason", out var reasonNode)
                ? reasonNode.GetString()
                : null;
            reason = string.IsNullOrWhiteSpace(reason) ? $"gemini_match={isMatch}" : reason.Trim();

            return new GeminiImageValidationResult(score, reason);
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractGeminiOutputText(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("candidates", out var candidates) || candidates.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var candidate in candidates.EnumerateArray())
            {
                if (!candidate.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                if (!content.TryGetProperty("parts", out var parts) || parts.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                var sb = new StringBuilder();
                foreach (var part in parts.EnumerateArray())
                {
                    if (part.TryGetProperty("text", out var text))
                    {
                        sb.Append(text.GetString());
                    }
                }

                var combined = sb.ToString().Trim();
                if (!string.IsNullOrWhiteSpace(combined))
                {
                    return combined;
                }
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static string? ExtractFirstJsonObject(string input)
    {
        var trimmed = input?.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return null;
        }

        var start = trimmed.IndexOf('{');
        if (start < 0)
        {
            return null;
        }

        var depth = 0;
        for (var i = start; i < trimmed.Length; i++)
        {
            if (trimmed[i] == '{')
            {
                depth++;
            }
            else if (trimmed[i] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return trimmed[start..(i + 1)];
                }
            }
        }

        return null;
    }

    private async Task<List<string>> HostImagesAsJpegAsync(IReadOnlyList<string> imageUrls, CancellationToken ct)
    {
        var results = new List<string>();
        var baseUrl = _webhookOptions.PublicBaseUrl;
        if (imageUrls.Count == 0 || string.IsNullOrWhiteSpace(baseUrl))
        {
            return results;
        }

        var client = _httpClientFactory.CreateClient("default");
        foreach (var imageUrl in imageUrls.Take(10))
        {
            if (!Uri.TryCreate(imageUrl, UriKind.Absolute, out var uri))
            {
                continue;
            }

            try
            {
                using var request = BuildImageFetchRequest(uri);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var bytes = await response.Content.ReadAsByteArrayAsync(ct);
                if (bytes.Length == 0 || bytes.Length > 8 * 1024 * 1024)
                {
                    continue;
                }

                var contentType = response.Content.Headers.ContentType?.MediaType;
                var jpegBytes = NormalizeToJpegBytes(bytes, contentType);
                if (jpegBytes is null || jpegBytes.Length == 0)
                {
                    continue;
                }

                var id = _mediaStore.Add(jpegBytes, "image/jpeg", TimeSpan.FromHours(4));
                var publicUrl = BuildPublicJpegUrl(baseUrl, id);
                if (!string.IsNullOrWhiteSpace(publicUrl))
                {
                    results.Add(publicUrl);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to host image as jpeg for autopilot: {ImageUrl}", imageUrl);
            }
        }

        return results
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static HttpRequestMessage BuildImageFetchRequest(Uri uri)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/jpeg"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/png", 0.9));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/*", 0.8));
        request.Headers.AcceptLanguage.ParseAdd("pt-BR,pt;q=0.9,en;q=0.8");
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        request.Headers.Referrer = new Uri(uri.GetLeftPart(UriPartial.Authority));
        return request;
    }

    private static byte[]? NormalizeToJpegBytes(byte[] input, string? contentType)
    {
        if (string.Equals(contentType, "image/jpeg", StringComparison.OrdinalIgnoreCase))
        {
            return input;
        }

        return ImageNormalizationSupport.TranscodeToJpeg(input, quality: 90);
    }

    private static string BuildPublicJpegUrl(string publicBaseUrl, string id)
    {
        var url = $"{publicBaseUrl.TrimEnd('/')}/media/{id}.jpeg";
        if (url.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) ||
            url.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase))
        {
            url += "?ngrok-skip-browser-warning=1";
        }

        return url;
    }

    private static bool IsLikelyWebpImageUrl(string? imageUrl)
    {
        if (string.IsNullOrWhiteSpace(imageUrl))
        {
            return false;
        }

        return Regex.IsMatch(imageUrl, @"\.webp(\?|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static string ResolveImageMimeType(string? contentType, string imageUrl)
    {
        if (!string.IsNullOrWhiteSpace(contentType) && contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
        {
            return contentType;
        }

        var extension = Path.GetExtension(imageUrl ?? string.Empty).ToLowerInvariant();
        return extension switch
        {
            ".png" => "image/png",
            ".webp" => "image/webp",
            ".gif" => "image/gif",
            ".bmp" => "image/bmp",
            _ => "image/jpeg"
        };
    }

    private static int ComputeImageUrlRelevanceScore(string productName, string store, string imageUrl)
    {
        if (string.IsNullOrWhiteSpace(imageUrl))
        {
            return 0;
        }

        var score = 35;
        var normalized = imageUrl.ToLowerInvariant();
        var tokens = ExtractProductTokens(productName, store);
        foreach (var token in tokens)
        {
            if (normalized.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                score += 16;
            }
        }

        if (normalized.Contains(store.Replace(" ", string.Empty).ToLowerInvariant(), StringComparison.OrdinalIgnoreCase))
        {
            score += 6;
        }

        if (Regex.IsMatch(normalized, @"\.(jpg|jpeg|png)(\?|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            score += 4;
        }

        foreach (var bad in NonProductImageTerms)
        {
            if (normalized.Contains(bad, StringComparison.OrdinalIgnoreCase))
            {
                score -= 18;
            }
        }

        return Math.Clamp(score, 0, 100);
    }

    private static List<string> ExtractProductTokens(string productName, string store)
    {
        var source = $"{productName} {store}".ToLowerInvariant();
        return Regex.Split(source, @"[^\p{L}\p{N}]+", RegexOptions.CultureInvariant)
            .Where(x => x.Length >= 3)
            .Where(x => !ImageTokenStopWords.Contains(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToList();
    }

    private static (List<string> Captions, string Hashtags) ExtractCaptionsAndHashtags(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return (new List<string>(), string.Empty);
        }

        var captions = new List<string>();
        foreach (Match match in Regex.Matches(
                     text,
                     @"Legenda\s+\d+[^\n]*\n(?<cap>[\s\S]*?)(?=\n\s*Legenda\s+\d+\b|\n\s*Hashtags\s+sugeridas\b|\z)",
                     RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var value = match.Groups["cap"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(value))
            {
                captions.Add(value);
            }
        }

        if (captions.Count == 0)
        {
            var lines = text.Replace("\r", string.Empty)
                .Split('\n', StringSplitOptions.None)
                .Select(x => x.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Where(x => !x.StartsWith("POST PARA INSTAGRAM", StringComparison.OrdinalIgnoreCase))
                .Where(x => !x.StartsWith("Produto:", StringComparison.OrdinalIgnoreCase))
                .Where(x => !x.StartsWith("Link afiliado:", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (lines.Count > 0)
            {
                captions.Add(string.Join("\n", lines.Take(12)));
            }
        }

        var hashtagLines = Regex.Match(
            text,
            @"Hashtags\s+sugeridas\s*:\s*(?<tags>[\s\S]*?)(?=\n\s*\w.*:|\z)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var hashtags = hashtagLines.Success
            ? string.Join(' ', Regex.Matches(hashtagLines.Groups["tags"].Value, @"#[A-Za-z0-9_À-ÖØ-öø-ÿ]+")
                .Select(x => x.Value)
                .Distinct(StringComparer.OrdinalIgnoreCase))
            : string.Join(' ', Regex.Matches(text, @"#[A-Za-z0-9_À-ÖØ-öø-ÿ]+")
                .Select(x => x.Value)
                .Distinct(StringComparer.OrdinalIgnoreCase));

        return (captions, hashtags.Trim());
    }

    private static string NormalizeHashtags(string hashtags, string store, string productName)
    {
        var tags = Regex.Matches(hashtags ?? string.Empty, @"#[A-Za-z0-9_À-ÖØ-öø-ÿ]+")
            .Select(m => m.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var fallback = new List<string> { "#achadinhos", "#ofertas", "#promocoes", "#descontos", "#custobeneficio" };
        var storeTag = store.Trim().ToLowerInvariant() switch
        {
            "amazon" => "#amazonbr",
            "mercado livre" => "#mercadolivre",
            "shopee" => "#shopeebrasil",
            "shein" => "#sheinbrasil",
            _ => string.Empty
        };
        if (!string.IsNullOrWhiteSpace(storeTag))
        {
            fallback.Add(storeTag);
        }

        foreach (var word in productName.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Take(2))
        {
            var cleaned = Regex.Replace(word, @"[^\wÀ-ÖØ-öø-ÿ]", string.Empty, RegexOptions.CultureInvariant);
            if (cleaned.Length >= 3)
            {
                fallback.Add($"#{cleaned.ToLowerInvariant()}");
            }
        }

        foreach (var tag in fallback)
        {
            if (tags.Count >= 8)
            {
                break;
            }

            if (!tags.Contains(tag, StringComparer.OrdinalIgnoreCase))
            {
                tags.Add(tag);
            }
        }

        return string.Join(' ', tags.Take(10));
    }

    private static string EnsureCaptionContainsCta(string caption, string keyword)
    {
        var text = FormatCaption(caption);
        if (string.IsNullOrWhiteSpace(text))
        {
            return $"Comente \"{keyword}\" para receber o link.";
        }

        var hasKeyword = Regex.IsMatch(text, $@"\b{Regex.Escape(keyword)}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (hasKeyword)
        {
            return text;
        }

        return $"{text}\n\nComente \"{keyword}\" para receber o link.";
    }

    private static string FormatCaption(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        var normalized = text.Replace("\r", string.Empty).Trim();
        normalized = Regex.Replace(normalized, @"\\n", "\n", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"[ \t]+", " ", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"\n{3,}", "\n\n", RegexOptions.CultureInvariant);
        return normalized.Trim();
    }

    private static string BuildKeyword(string productName, string store)
    {
        var tokens = productName
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => Regex.Replace(x, @"[^\wÀ-ÖØ-öø-ÿ]", string.Empty, RegexOptions.CultureInvariant))
            .Where(x => x.Length >= 3)
            .ToList();

        var candidate = tokens.FirstOrDefault()
                        ?? store.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()
                        ?? "OFERTA";
        candidate = candidate.ToUpperInvariant();
        return candidate.Length > 18 ? candidate[..18] : candidate;
    }

    private static List<string> NormalizeExternalUrls(IEnumerable<string>? urls, int max)
    {
        if (urls is null)
        {
            return new List<string>();
        }

        return urls
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Where(x => Uri.TryCreate(x, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, max))
            .ToList();
    }

    private static string NormalizeUrlKey(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return (url ?? string.Empty).Trim().ToLowerInvariant();
        }

        var keepQuery = ParseQuery(uri.Query)
            .Where(kv => !IgnoredTrackingKeys.Contains(kv.Key))
            .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ThenBy(kv => kv.Value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var query = keepQuery.Count == 0
            ? string.Empty
            : "?" + string.Join("&", keepQuery.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return $"{uri.Scheme.ToLowerInvariant()}://{uri.Host.ToLowerInvariant()}{uri.AbsolutePath}{query}".TrimEnd('/');
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return dict;
        }

        var q = query.TrimStart('?');
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
            {
                continue;
            }

            var key = Uri.UnescapeDataString(part[..idx]);
            var value = Uri.UnescapeDataString(part[(idx + 1)..]);
            if (!string.IsNullOrWhiteSpace(key))
            {
                dict[key] = value;
            }
        }

        return dict;
    }

    private static readonly HashSet<string> IgnoredTrackingKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "tag", "matt_tool", "matt_word", "smtt", "uls_trackid", "affiliateid", "affiliate_id", "url_from",
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "clkid", "clickid"
    };

    private static readonly HashSet<string> NonProductImageTerms = new(StringComparer.OrdinalIgnoreCase)
    {
        "logo", "icon", "sprite", "avatar", "banner", "placeholder", "thumb", "thumbnail", "loading"
    };

    private static readonly HashSet<string> ImageTokenStopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "com", "para", "sem", "mais", "de", "da", "do", "e", "na", "no", "um", "uma",
        "store", "produto", "oferta", "ofertas", "shop", "shopping", "mercado", "livre"
    };

    private static readonly HashSet<string> GenericProductNameTerms = new(StringComparer.OrdinalIgnoreCase)
    {
        "produto", "item", "oferta", "ofertas", "promocao", "promo", "desconto", "loja", "shop", "marketplace", "achadinho"
    };

    private static readonly HashSet<string> MarketplaceTitleTerms = new(StringComparer.OrdinalIgnoreCase)
    {
        "amazon", "mercado livre", "mercadolivre", "shopee", "shein", "loja", "store", "marketplace", "brasil", "oficial"
    };

    private static readonly HashSet<string> UrlNoiseSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "dp", "gp", "p", "d", "product", "products", "produto", "produtos", "item", "items", "offer", "oferta", "shop", "loja"
    };

    private static readonly HashSet<string> InstagramEngagementTerms = new(StringComparer.OrdinalIgnoreCase)
    {
        "kit", "organizador", "cozinha", "casa", "decor", "decoracao", "beleza", "maquiagem", "skincare", "perfume",
        "fone", "headset", "smart", "gamer", "led", "fitness", "academia", "moda", "vestido", "tenis",
        "sapato", "bolsa", "bebe", "infantil", "pet"
    };

    private static string? ExtractFirstUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = UrlRegex.Match(text);
        return match.Success ? match.Value.Trim().TrimEnd('.', ',', ';', ')') : null;
    }

    private static string? TryExtractProductNameFromUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var query = ParseQuery(uri.Query);
        foreach (var key in new[] { "title", "name", "product", "produto", "description", "desc" })
        {
            if (!query.TryGetValue(key, out var value))
            {
                continue;
            }

            var normalized = NormalizeProductTitle(value, string.Empty);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return normalized;
            }
        }

        var segments = uri.AbsolutePath
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => Uri.UnescapeDataString(s).Trim())
            .ToList();
        if (segments.Count == 0)
        {
            return null;
        }

        string? best = null;
        for (var i = segments.Count - 1; i >= 0; i--)
        {
            var raw = segments[i];
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var lower = raw.ToLowerInvariant();
            if (UrlNoiseSegments.Contains(lower))
            {
                continue;
            }

            raw = raw.Replace('-', ' ').Replace('_', ' ');
            raw = Regex.Replace(raw, @"\b[a-z]{1,3}\d{4,}\b", " ", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            raw = Regex.Replace(raw, @"\b\d{5,}\b", " ", RegexOptions.CultureInvariant);
            raw = Regex.Replace(raw, @"[^\wÀ-ÖØ-öø-ÿ ]", " ", RegexOptions.CultureInvariant);
            raw = Regex.Replace(raw, @"\s+", " ", RegexOptions.CultureInvariant).Trim();

            if (raw.Length < 6 || LooksOpaqueProductName(raw))
            {
                continue;
            }

            best = raw;
            break;
        }

        if (string.IsNullOrWhiteSpace(best))
        {
            return null;
        }

        return best.Length > 110 ? best[..110].TrimEnd() : best;
    }

    private static string FirstNotEmpty(params string?[] values)
        => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim() ?? string.Empty;

    private sealed record ImageSelectionResult(
        List<string> OrderedUrls,
        string? BestImageUrl,
        int? BestScore,
        string? BestReason);

    private sealed record ImageCandidateEvaluation(
        string Url,
        int Score,
        string Reason,
        int OriginalIndex);

    private sealed record GeminiImageValidationResult(
        int Score,
        string Reason);

    private sealed class CandidateScore
    {
        public string Key { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public string Store { get; set; } = "Unknown";
        public string DataSource { get; set; } = "meta";
        public string? ProductName { get; set; }
        public string? SelectedImageUrl { get; set; }
        public int? ImageMatchScore { get; set; }
        public string? ImageMatchReason { get; set; }
        public int SalesSignal { get; set; }
        public int ReturnSignal { get; set; }
        public int DiscountSignal { get; set; }
        public int RecencySignal { get; set; }
        public int EngagementSignal { get; set; }
        public int FinalScore { get; set; }
        public DateTimeOffset LatestTimestamp { get; set; }
        public string? Note { get; set; }
    }
}


