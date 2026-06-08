using System.Net.Http.Headers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Media;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreStoryDraftService
{
    private const string SourceOrigin = "mercadolivre_scout_story";
    private const int StorySelectionLookbackHours = 2;
    private const int StoryCandidateRetentionHours = 8;

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IMediaStore _mediaStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly StoryAutoPublishService _storyAutoPublishService;
    private readonly WebhookOptions _webhookOptions;
    private readonly EvolutionOptions _evolutionOptions;
    private readonly ILogger<MercadoLivreStoryDraftService> _logger;

    public MercadoLivreStoryDraftService(
        IHttpClientFactory httpClientFactory,
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        IMediaStore mediaStore,
        IWhatsAppGateway whatsAppGateway,
        StoryAutoPublishService storyAutoPublishService,
        IOptions<WebhookOptions> webhookOptions,
        IOptions<EvolutionOptions> evolutionOptions,
        ILogger<MercadoLivreStoryDraftService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _mediaStore = mediaStore;
        _whatsAppGateway = whatsAppGateway;
        _storyAutoPublishService = storyAutoPublishService;
        _webhookOptions = webhookOptions.Value;
        _evolutionOptions = evolutionOptions.Value;
        _logger = logger;
    }

    public async Task<MercadoLivreStoryDraftRunResult> CreateDraftsAsync(
        IReadOnlyList<MercadoLivreAffiliateScoutOffer> offers,
        MercadoLivreAffiliateScoutSettings settings,
        CancellationToken ct)
    {
        var result = new MercadoLivreStoryDraftRunResult();
        if (!settings.CreateStoryDrafts)
        {
            return result;
        }

        var nowUtc = DateTimeOffset.UtcNow;
        var recentCandidates = await UpdateRecentCandidatesAsync(offers, nowUtc, ct);
        var allDrafts = await _publishStore.ListAsync(ct);
        var slot = GetCurrentStorySlot(settings, allDrafts, nowUtc);
        if (!slot.HasValue)
        {
            result.Message = "no_story_slot_due";
            return result;
        }

        var usedKeys = LoadRecentStoryKeys(allDrafts, settings, nowUtc);
        var bestCandidate = recentCandidates
            .Where(candidate => candidate.CapturedAtUtc >= nowUtc.AddHours(-StorySelectionLookbackHours))
            .Where(candidate => !string.IsNullOrWhiteSpace(candidate.Key) && !usedKeys.Contains(candidate.Key))
            .OrderByDescending(candidate => candidate.Score)
            .ThenByDescending(candidate => candidate.CapturedAtUtc)
            .FirstOrDefault();
        if (bestCandidate is null)
        {
            result.SkippedCount = recentCandidates.Count;
            result.Message = "no_story_candidate_in_window";
            return result;
        }

        var offer = bestCandidate.ToOffer();
        var offerUrl = FirstNotEmpty(offer.SharedUrl, offer.ProductUrl);
        try
        {
            var mediaUrl = await BuildStoryMediaUrlAsync(offer, ct);
            var originalImageUrl = string.IsNullOrWhiteSpace(offer.ImageUrl) ? null : offer.ImageUrl!.Trim();
            var publishImageUrls = new List<string>();
            var catalogImageUrls = new List<string>();
            if (!string.IsNullOrWhiteSpace(originalImageUrl))
            {
                catalogImageUrls.Add(originalImageUrl);
            }

            if (!string.IsNullOrWhiteSpace(mediaUrl))
            {
                publishImageUrls.Add(mediaUrl);
            }
            else if (!string.IsNullOrWhiteSpace(originalImageUrl))
            {
                publishImageUrls.Add(originalImageUrl);
            }

            var draft = BuildDraft(offer, offerUrl, publishImageUrls, catalogImageUrls, slot.Value);
            await _publishStore.SaveAsync(draft, ct);
            await AppendLogAsync(
                "mercadolivre_story_draft_created",
                true,
                draft.Id,
                $"Url={Sanitize(offerUrl)};ScheduledFor={slot.Value:O};ImageEdited={!string.IsNullOrWhiteSpace(mediaUrl)};CatalogImageOriginal={catalogImageUrls.Count > 0};CatalogTarget={draft.CatalogTarget};SelectionScore={bestCandidate.Score:0.##};WindowHours={StorySelectionLookbackHours}",
                ct);

            result.CreatedCount = 1;

            if (settings.StoryAutoApproveAndPublish)
            {
                var autoPublish = await _storyAutoPublishService.ApprovePublishAndVerifyAsync(draft.Id, ct);
                await SendAutoPublishResultAsync(draft, settings, autoPublish, ct);
            }
            else if (settings.StorySendForApproval)
            {
                var approval = await SendApprovalAsync(draft, settings, ct);
                if (approval.Success)
                {
                    result.ApprovalSentCount++;
                }
                else
                {
                    result.ApprovalFailedCount++;
                }
            }
        }
        catch (Exception ex)
        {
            result.FailedCount++;
            _logger.LogWarning(ex, "Falha ao criar story ML para oferta {Title}", offer.Title);
            await AppendLogAsync("mercadolivre_story_draft_failed", false, null, $"Url={Sanitize(offerUrl)};Error={Sanitize(ex.Message)}", ct);
        }

        result.Success = true;
        result.Message = $"created={result.CreatedCount};approvalSent={result.ApprovalSentCount};skipped={result.SkippedCount};failed={result.FailedCount}";
        return result;
    }

    private async Task<List<MercadoLivreStoryCandidate>> UpdateRecentCandidatesAsync(
        IReadOnlyList<MercadoLivreAffiliateScoutOffer> offers,
        DateTimeOffset nowUtc,
        CancellationToken ct)
    {
        var candidates = await ReadCandidatesAsync(ct);
        foreach (var offer in offers)
        {
            var key = NormalizeUrlKey(FirstNotEmpty(offer.SharedUrl, offer.ProductUrl));
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            candidates.RemoveAll(candidate => string.Equals(candidate.Key, key, StringComparison.OrdinalIgnoreCase));
            candidates.Add(MercadoLivreStoryCandidate.FromOffer(offer, key, nowUtc));
        }

        var cutoff = nowUtc.AddHours(-StoryCandidateRetentionHours);
        candidates = candidates
            .Where(candidate => candidate.CapturedAtUtc >= cutoff)
            .OrderByDescending(candidate => candidate.CapturedAtUtc)
            .Take(500)
            .ToList();
        await WriteCandidatesAsync(candidates, ct);
        return candidates;
    }

    private async Task<List<MercadoLivreStoryCandidate>> ReadCandidatesAsync(CancellationToken ct)
    {
        var path = StoryCandidatesPath();
        if (!File.Exists(path))
        {
            return new List<MercadoLivreStoryCandidate>();
        }

        var json = await File.ReadAllTextAsync(path, ct);
        return string.IsNullOrWhiteSpace(json)
            ? new List<MercadoLivreStoryCandidate>()
            : JsonSerializer.Deserialize<List<MercadoLivreStoryCandidate>>(json) ?? new List<MercadoLivreStoryCandidate>();
    }

    private async Task WriteCandidatesAsync(List<MercadoLivreStoryCandidate> candidates, CancellationToken ct)
    {
        var path = StoryCandidatesPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(candidates), ct);
    }

    private static string StoryCandidatesPath()
        => Path.Combine(AppContext.BaseDirectory, "data", "mercadolivre-story-candidates.json");

    internal static IReadOnlyList<DateTimeOffset> GetNextAvailableStorySlots(
        MercadoLivreAffiliateScoutSettings settings,
        IReadOnlyList<InstagramPublishDraft> existingDrafts,
        DateTimeOffset nowUtc)
    {
        var timeZone = ResolveBrazilTimeZone();
        var localNow = TimeZoneInfo.ConvertTime(nowUtc, timeZone);
        var scheduleTimes = (settings.StoryScheduleTimes ?? new List<string>())
            .Select(ParseScheduleTime)
            .Where(x => x.HasValue)
            .Select(x => x!.Value)
            .OrderBy(x => x)
            .ToList();
        if (scheduleTimes.Count == 0)
        {
            scheduleTimes = new List<TimeSpan> { new(9, 0, 0), new(11, 0, 0), new(13, 0, 0), new(15, 0, 0), new(17, 0, 0), new(19, 0, 0), new(21, 0, 0), new(23, 0, 0) };
        }

        var maxPerDay = Math.Clamp(settings.StoryDraftsPerDay, 1, 24);
        var occupied = existingDrafts
            .Where(IsMercadoLivreStoryDraft)
            .Where(x => x.ScheduledFor.HasValue)
            .Select(x => TimeZoneInfo.ConvertTime(x.ScheduledFor!.Value, timeZone))
            .Select(x => x.DateTime)
            .ToList();

        var slots = new List<DateTimeOffset>();
        for (var dayOffset = 0; dayOffset < 14 && slots.Count < maxPerDay; dayOffset++)
        {
            var day = localNow.Date.AddDays(dayOffset);
            var occupiedOnDay = occupied.Count(x => x.Date == day);
            if (occupiedOnDay >= maxPerDay)
            {
                continue;
            }

            foreach (var scheduleTime in scheduleTimes)
            {
                if (slots.Count >= maxPerDay || occupiedOnDay >= maxPerDay)
                {
                    break;
                }

                var candidateLocal = day.Add(scheduleTime);
                if (candidateLocal <= localNow.DateTime)
                {
                    continue;
                }

                if (occupied.Any(x => x.Date == candidateLocal.Date && Math.Abs((x.TimeOfDay - candidateLocal.TimeOfDay).TotalMinutes) < 1))
                {
                    continue;
                }

                slots.Add(ToUtc(candidateLocal, timeZone));
                occupiedOnDay++;
            }
        }

        return slots;
    }

    internal static DateTimeOffset? GetCurrentStorySlot(
        MercadoLivreAffiliateScoutSettings settings,
        IReadOnlyList<InstagramPublishDraft> existingDrafts,
        DateTimeOffset nowUtc)
    {
        var timeZone = ResolveBrazilTimeZone();
        var localNow = TimeZoneInfo.ConvertTime(nowUtc, timeZone);
        var scheduleTimes = ResolveScheduleTimes(settings);
        var latestDueLocal = scheduleTimes
            .Select(time => localNow.Date.Add(time))
            .Where(candidate => candidate <= localNow.DateTime)
            .OrderByDescending(candidate => candidate)
            .FirstOrDefault();
        if (latestDueLocal == default)
        {
            return null;
        }

        var latestDueUtc = ToUtc(latestDueLocal, timeZone);
        var alreadyCreated = existingDrafts
            .Where(IsMercadoLivreStoryDraft)
            .Where(draft => !string.Equals(draft.Status, "failed", StringComparison.OrdinalIgnoreCase))
            .Where(draft => draft.ScheduledFor.HasValue)
            .Any(draft => Math.Abs((draft.ScheduledFor!.Value - latestDueUtc).TotalMinutes) < 1);
        return alreadyCreated ? null : latestDueUtc;
    }

    private static List<TimeSpan> ResolveScheduleTimes(MercadoLivreAffiliateScoutSettings settings)
    {
        var scheduleTimes = (settings.StoryScheduleTimes ?? new List<string>())
            .Select(ParseScheduleTime)
            .Where(x => x.HasValue)
            .Select(x => x!.Value)
            .OrderBy(x => x)
            .ToList();
        return scheduleTimes.Count > 0
            ? scheduleTimes
            : new List<TimeSpan> { new(9, 0, 0), new(11, 0, 0), new(13, 0, 0), new(15, 0, 0), new(17, 0, 0), new(19, 0, 0), new(21, 0, 0), new(23, 0, 0) };
    }

    private async Task<string?> BuildStoryMediaUrlAsync(MercadoLivreAffiliateScoutOffer offer, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(offer.ImageUrl) || string.IsNullOrWhiteSpace(_webhookOptions.PublicBaseUrl))
        {
            return null;
        }

        var client = _httpClientFactory.CreateClient("default");
        using var request = new HttpRequestMessage(HttpMethod.Get, offer.ImageUrl.Trim());
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/jpeg"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/png", 0.9));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/*", 0.8));
        request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AchadinhosBot/1.0");

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var bytes = await response.Content.ReadAsByteArrayAsync(ct);
        if (bytes.Length == 0 || bytes.Length > 8 * 1024 * 1024)
        {
            return null;
        }

        var edited = MercadoLivreStoryImageComposer.Compose(bytes);
        if (edited is null || edited.Length == 0)
        {
            return null;
        }

        var id = _mediaStore.Add(edited, "image/jpeg", TimeSpan.FromDays(2));
        return BuildPublicMediaUrl(_webhookOptions.PublicBaseUrl, id);
    }

    private async Task<WhatsAppSendResult> SendApprovalAsync(
        InstagramPublishDraft draft,
        MercadoLivreAffiliateScoutSettings settings,
        CancellationToken ct)
    {
        var groupId = settings.StoryApprovalWhatsAppGroupId?.Trim();
        if (string.IsNullOrWhiteSpace(groupId))
        {
            await AppendLogAsync("mercadolivre_story_approval_missing", true, draft.Id, "Channel=whatsapp", ct);
            return new WhatsAppSendResult(false, "Grupo de aprovacao nao configurado.");
        }

        var instanceName = FirstNotEmpty(settings.StoryApprovalWhatsAppInstanceName, _evolutionOptions.InstanceName, "ZapOfertas");
        var message = BuildApprovalMessage(draft);
        var imageUrl = draft.ImageUrls.FirstOrDefault();
        WhatsAppSendResult send;
        if (!string.IsNullOrWhiteSpace(imageUrl))
        {
            send = await _whatsAppGateway.SendImageUrlAsync(instanceName, groupId, imageUrl, message, "image/jpeg", "story-ml.jpg", ct);
        }
        else
        {
            send = await _whatsAppGateway.SendTextAsync(instanceName, groupId, message, ct);
        }

        await AppendLogAsync(
            "mercadolivre_story_approval_sent",
            send.Success,
            draft.Id,
            $"Target={groupId};Instance={Sanitize(instanceName)};Message={Sanitize(send.Message)}",
            ct);
        return send;
    }

    private async Task<WhatsAppSendResult> SendAutoPublishResultAsync(
        InstagramPublishDraft draft,
        MercadoLivreAffiliateScoutSettings settings,
        StoryAutoPublishResult result,
        CancellationToken ct)
    {
        var groupId = settings.StoryApprovalWhatsAppGroupId?.Trim();
        if (string.IsNullOrWhiteSpace(groupId))
        {
            await AppendLogAsync("mercadolivre_story_auto_publish_feedback_missing", true, draft.Id, "Channel=whatsapp", ct);
            return new WhatsAppSendResult(false, "Grupo de feedback nao configurado.");
        }

        var instanceName = FirstNotEmpty(settings.StoryApprovalWhatsAppInstanceName, _evolutionOptions.InstanceName, "ZapOfertas");
        var send = await _whatsAppGateway.SendTextAsync(instanceName, groupId, BuildAutoPublishFeedbackMessage(draft, result), ct);
        await AppendLogAsync(
            "mercadolivre_story_auto_publish_feedback_sent",
            send.Success,
            draft.Id,
            $"Target={groupId};Instance={Sanitize(instanceName)};Success={result.Success};Message={Sanitize(send.Message)}",
            ct);
        return send;
    }

    private static string BuildAutoPublishFeedbackMessage(InstagramPublishDraft draft, StoryAutoPublishResult result)
    {
        var status = result.Success ? "✅" : "⚠️";
        return string.Join(Environment.NewLine, new[]
        {
            $"{status} *STORY ML - APROVACAO AUTOMATICA*",
            string.Empty,
            $"Draft: `{draft.Id[..Math.Min(8, draft.Id.Length)]}`",
            $"Produto: *{draft.ProductName}*",
            $"Stories: {(result.InstagramPosted ? "ok" : $"falhou ({result.InstagramError ?? "sem detalhe"})")}",
            $"Catalogo: {(result.CatalogVerified ? "ok" : $"falhou ({result.CatalogError ?? "nao confirmado"})")}",
            $"WhatsApp: {(result.WhatsAppPosted ? "ok" : $"falhou ({result.WhatsAppError ?? "nao confirmado"})")}"
        });
    }

    private static InstagramPublishDraft BuildDraft(
        MercadoLivreAffiliateScoutOffer offer,
        string offerUrl,
        List<string> publishImageUrls,
        List<string> catalogImageUrls,
        DateTimeOffset scheduledFor)
    {
        var productName = FirstNotEmpty(offer.Title, "Oferta Mercado Livre");
        var price = FirstNotEmpty(offer.PriceText, "confira no catalogo");
        var caption = BuildCaption(productName, price);
        return new InstagramPublishDraft
        {
            PostType = "story",
            ProductName = productName,
            Caption = caption,
            CaptionOptions = new List<string> { caption },
            SelectedCaptionIndex = 1,
            Hashtags = "#mercadolivre #achadinhos #ofertas #promocoes",
            OriginalOfferUrl = offerUrl,
            OfferUrl = offerUrl,
            ImageUrls = publishImageUrls,
            SuggestedImageUrls = catalogImageUrls.Count > 0 ? catalogImageUrls : publishImageUrls,
            Ctas = new List<InstagramCtaOption>
            {
                new() { Keyword = "LINK", Link = offerUrl }
            },
            AutoReplyEnabled = true,
            AutoReplyKeyword = "LINK",
            AutoReplyLink = offerUrl,
            AutoReplyMessage = $"Link da oferta: {offerUrl}",
            Store = "Mercado Livre",
            CurrentPrice = price,
            ScheduledFor = scheduledFor,
            SendToCatalog = true,
            CatalogTarget = CatalogTargets.Prod,
            CatalogIntentLocked = true,
            SourceDataOrigin = SourceOrigin,
            ProcessName = "mercadolivre_scout_story",
            Status = "draft"
        };
    }

    private static string BuildCaption(string productName, string price)
        => new StringBuilder()
            .AppendLine($"Oferta no Mercado Livre: {productName}")
            .AppendLine($"Preco: {price}")
            .AppendLine()
            .AppendLine("Link na bio, acesse o catalogo do Rei das Ofertas.")
            .ToString()
            .Trim();

    private static string BuildApprovalMessage(InstagramPublishDraft draft)
    {
        var scheduled = draft.ScheduledFor.HasValue
            ? TimeZoneInfo.ConvertTime(draft.ScheduledFor.Value, ResolveBrazilTimeZone()).ToString("dd/MM/yyyy HH:mm 'BRT'")
            : "sem horario";
        return
            "\U0001F4F2 *STORY ML - APROVACAO*\n\n" +
            $"Draft: `{draft.Id[..Math.Min(8, draft.Id.Length)]}`\n" +
            $"Produto: *{draft.ProductName}*\n" +
            $"Preco: *{FirstNotEmpty(draft.CurrentPrice, "-")}*\n" +
            $"Agendado: *{scheduled}*\n" +
            $"Catalogo: *producao*\n" +
            $"Link: {FirstNotEmpty(draft.OfferUrl, draft.OriginalOfferUrl, "-")}\n\n" +
            "Comandos: /ig revisar ou /ig confirmar usando o ID acima.";
    }

    private HashSet<string> LoadRecentStoryKeys(
        IReadOnlyList<InstagramPublishDraft> drafts,
        MercadoLivreAffiliateScoutSettings settings,
        DateTimeOffset nowUtc)
    {
        var cutoff = nowUtc.AddHours(-Math.Clamp(settings.RepeatWindowHours, 1, 168));
        return drafts
            .Where(IsMercadoLivreStoryDraft)
            .Where(x => x.CreatedAt >= cutoff && !string.Equals(x.Status, "failed", StringComparison.OrdinalIgnoreCase))
            .SelectMany(x => new[] { x.OfferUrl, x.OriginalOfferUrl }.Concat(x.Ctas.Select(cta => cta.Link)))
            .Select(NormalizeUrlKey)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class MercadoLivreStoryCandidate
    {
        public string Key { get; set; } = string.Empty;
        public string? Title { get; set; }
        public string? ProductUrl { get; set; }
        public string? SharedUrl { get; set; }
        public string? PriceText { get; set; }
        public string? CommissionText { get; set; }
        public string? ImageUrl { get; set; }
        public decimal Price { get; set; }
        public decimal CommissionPercent { get; set; }
        public decimal Score { get; set; }
        public DateTimeOffset CapturedAtUtc { get; set; }

        public static MercadoLivreStoryCandidate FromOffer(MercadoLivreAffiliateScoutOffer offer, string key, DateTimeOffset capturedAtUtc)
        {
            var price = MercadoLivreAffiliateScoutWorker.TryParsePrice(offer.PriceText);
            var commission = MercadoLivreAffiliateScoutWorker.TryParseCommission(offer.CommissionText);
            return new MercadoLivreStoryCandidate
            {
                Key = key,
                Title = offer.Title,
                ProductUrl = offer.ProductUrl,
                SharedUrl = offer.SharedUrl,
                PriceText = offer.PriceText,
                CommissionText = offer.CommissionText,
                ImageUrl = offer.ImageUrl,
                Price = price,
                CommissionPercent = commission,
                Score = ComputeScore(offer, price, commission),
                CapturedAtUtc = capturedAtUtc
            };
        }

        public MercadoLivreAffiliateScoutOffer ToOffer()
            => new(Title, ProductUrl, SharedUrl, PriceText, CommissionText, ImageUrl);

        private static decimal ComputeScore(MercadoLivreAffiliateScoutOffer offer, decimal price, decimal commission)
        {
            var normalizedTitle = NormalizeTitle(offer.Title);
            var estimatedCommissionValue = price * commission / 100m;
            var priceBonus = price switch
            {
                >= 50m and <= 250m => 18m,
                > 250m and <= 600m => 12m,
                > 600m => 6m,
                _ => 3m
            };
            var interestBonus = ContainsAny(
                normalizedTitle,
                "tenis", "perfume", "air fryer", "fone", "celular", "smartphone", "kit", "camiseta", "calca",
                "organizador", "panela", "copo", "garrafa", "mixer", "cadeira", "sofa")
                ? 12m
                : 0m;
            var imageBonus = string.IsNullOrWhiteSpace(offer.ImageUrl) ? 0m : 10m;

            return (commission * 3m) + estimatedCommissionValue + priceBonus + interestBonus + imageBonus;
        }

        private static string NormalizeTitle(string? value)
        {
            var normalized = (value ?? string.Empty).Normalize(NormalizationForm.FormD).ToLowerInvariant();
            return new string(normalized.Where(ch => CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.NonSpacingMark).ToArray());
        }

        private static bool ContainsAny(string text, params string[] terms)
            => terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));
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

    private static bool IsMercadoLivreStoryDraft(InstagramPublishDraft draft)
        => string.Equals(draft.PostType, "story", StringComparison.OrdinalIgnoreCase) &&
           string.Equals(draft.SourceDataOrigin, SourceOrigin, StringComparison.OrdinalIgnoreCase);

    private static string BuildPublicMediaUrl(string publicBaseUrl, string id)
    {
        var url = $"{publicBaseUrl.TrimEnd('/')}/media/{id}.jpeg";
        if (url.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) ||
            url.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase))
        {
            url += "?ngrok-skip-browser-warning=1";
        }

        return url;
    }

    private static TimeSpan? ParseScheduleTime(string? value)
        => TimeSpan.TryParse(value, out var parsed) && parsed >= TimeSpan.Zero && parsed < TimeSpan.FromDays(1)
            ? parsed
            : null;

    private static DateTimeOffset ToUtc(DateTime localDateTime, TimeZoneInfo timeZone)
        => new DateTimeOffset(localDateTime, timeZone.GetUtcOffset(localDateTime)).ToUniversalTime();

    private static TimeZoneInfo ResolveBrazilTimeZone()
    {
        foreach (var id in new[] { "America/Sao_Paulo", "E. South America Standard Time" })
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(id);
            }
            catch (TimeZoneNotFoundException)
            {
            }
            catch (InvalidTimeZoneException)
            {
            }
        }

        return TimeZoneInfo.Local;
    }

    private static string NormalizeUrlKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim().TrimEnd('.', ',', ';', ')', ']', '>');
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            return trimmed.ToLowerInvariant();
        }

        return $"{uri.Scheme.ToLowerInvariant()}://{uri.Host.ToLowerInvariant()}{uri.AbsolutePath}".TrimEnd('/');
    }

    private static string FirstNotEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? string.Empty;

    private static string Sanitize(string? value)
        => (value ?? string.Empty).Replace(';', ',').ReplaceLineEndings(" ").Trim();
}

public sealed class MercadoLivreStoryDraftRunResult
{
    public bool Success { get; set; }
    public int CreatedCount { get; set; }
    public int SkippedCount { get; set; }
    public int FailedCount { get; set; }
    public int ApprovalSentCount { get; set; }
    public int ApprovalFailedCount { get; set; }
    public string? Message { get; set; }
}
