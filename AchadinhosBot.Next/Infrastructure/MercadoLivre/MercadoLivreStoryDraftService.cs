using System.Net.Http.Headers;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
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

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IMediaStore _mediaStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly WebhookOptions _webhookOptions;
    private readonly EvolutionOptions _evolutionOptions;
    private readonly ILogger<MercadoLivreStoryDraftService> _logger;

    public MercadoLivreStoryDraftService(
        IHttpClientFactory httpClientFactory,
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        IMediaStore mediaStore,
        IWhatsAppGateway whatsAppGateway,
        IOptions<WebhookOptions> webhookOptions,
        IOptions<EvolutionOptions> evolutionOptions,
        ILogger<MercadoLivreStoryDraftService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _mediaStore = mediaStore;
        _whatsAppGateway = whatsAppGateway;
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
        if (!settings.CreateStoryDrafts || offers.Count == 0)
        {
            return result;
        }

        var allDrafts = await _publishStore.ListAsync(ct);
        var nowUtc = DateTimeOffset.UtcNow;
        var slots = GetNextAvailableStorySlots(settings, allDrafts, nowUtc)
            .Take(Math.Clamp(settings.StoryDraftsPerDay, 1, 24))
            .ToList();
        if (slots.Count == 0)
        {
            result.Message = "no_story_slots_available";
            return result;
        }

        var usedKeys = LoadRecentStoryKeys(allDrafts, settings, nowUtc);
        foreach (var offer in offers)
        {
            if (result.CreatedCount >= slots.Count)
            {
                break;
            }

            var offerUrl = FirstNotEmpty(offer.SharedUrl, offer.ProductUrl);
            var key = NormalizeUrlKey(offerUrl);
            if (string.IsNullOrWhiteSpace(key) || usedKeys.Contains(key))
            {
                result.SkippedCount++;
                continue;
            }

            try
            {
                var scheduledFor = slots[result.CreatedCount];
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

                var draft = BuildDraft(offer, offerUrl, publishImageUrls, catalogImageUrls, scheduledFor);
                await _publishStore.SaveAsync(draft, ct);
                await AppendLogAsync(
                    "mercadolivre_story_draft_created",
                    true,
                    draft.Id,
                    $"Url={Sanitize(offerUrl)};ScheduledFor={scheduledFor:O};ImageEdited={!string.IsNullOrWhiteSpace(mediaUrl)};CatalogImageOriginal={catalogImageUrls.Count > 0};CatalogTarget={draft.CatalogTarget}",
                    ct);

                result.CreatedCount++;
                usedKeys.Add(key);

                if (settings.StorySendForApproval)
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
        }

        result.Success = true;
        result.Message = $"created={result.CreatedCount};approvalSent={result.ApprovalSentCount};skipped={result.SkippedCount};failed={result.FailedCount}";
        return result;
    }

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
