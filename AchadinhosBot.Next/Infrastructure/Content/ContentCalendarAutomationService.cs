using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Content;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Infrastructure.Instagram;

namespace AchadinhosBot.Next.Infrastructure.Content;

public sealed class ContentCalendarAutomationService
{
    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex HashtagRegex = new(@"#[A-Za-z0-9_À-ÿ]+", RegexOptions.CultureInvariant);

    private readonly IContentCalendarStore _calendarStore;
    private readonly ISettingsStore _settingsStore;
    private readonly IInstagramPostComposer _instagramComposer;
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly InstagramLinkMetaService _instagramMetaService;
    private readonly ILogger<ContentCalendarAutomationService> _logger;

    public ContentCalendarAutomationService(
        IContentCalendarStore calendarStore,
        ISettingsStore settingsStore,
        IInstagramPostComposer instagramComposer,
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        IHttpClientFactory httpClientFactory,
        InstagramLinkMetaService instagramMetaService,
        ILogger<ContentCalendarAutomationService> logger)
    {
        _calendarStore = calendarStore;
        _settingsStore = settingsStore;
        _instagramComposer = instagramComposer;
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _httpClientFactory = httpClientFactory;
        _instagramMetaService = instagramMetaService;
        _logger = logger;
    }

    public async Task<ContentCalendarItem> CreateAsync(ContentCalendarCreateRequest request, CancellationToken ct)
    {
        var item = new ContentCalendarItem
        {
            ScheduledAt = request.ScheduledAt ?? DateTimeOffset.UtcNow,
            PostType = NormalizePostType(request.PostType),
            SourceInput = (request.SourceInput ?? string.Empty).Trim(),
            OfferContext = (request.OfferContext ?? string.Empty).Trim(),
            MediaUrl = (request.MediaUrl ?? string.Empty).Trim(),
            OfferUrl = (request.OfferUrl ?? string.Empty).Trim(),
            Keyword = NormalizeKeyword(request.Keyword),
            Hashtags = NormalizeHashtags(request.Hashtags),
            GeneratedCaption = (request.GeneratedCaption ?? string.Empty).Trim(),
            AutoPublish = request.AutoPublish ?? true,
            ReferenceUrl = (request.ReferenceUrl ?? string.Empty).Trim(),
            ReferenceCaption = (request.ReferenceCaption ?? string.Empty).Trim(),
            ReferenceMediaUrl = (request.ReferenceMediaUrl ?? string.Empty).Trim(),
            Status = "planned"
        };
        item.SourceInput = ResolveSourceInput(item);
        item.UpdatedAt = DateTimeOffset.UtcNow;
        await _calendarStore.SaveAsync(item, ct);
        return item;
    }

    public async Task<ContentCalendarItem> ImportReferenceAsync(ContentReferenceImportRequest request, CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        var instaSettings = settings.InstagramPosts ?? new InstagramPostSettings();

        var item = new ContentCalendarItem
        {
            ScheduledAt = request.ScheduledAt ?? DateTimeOffset.UtcNow,
            PostType = NormalizePostType(request.PostType),
            ReferenceUrl = (request.ReferenceUrl ?? string.Empty).Trim(),
            ReferenceCaption = (request.ReferenceCaption ?? string.Empty).Trim(),
            ReferenceMediaUrl = (request.ReferenceMediaUrl ?? string.Empty).Trim(),
            OfferUrl = (request.OfferUrl ?? string.Empty).Trim(),
            OfferContext = (request.OfferContext ?? string.Empty).Trim(),
            Keyword = NormalizeKeyword(request.Keyword),
            Hashtags = NormalizeHashtags(request.Hashtags),
            AutoPublish = request.AutoPublish ?? true,
            Status = "planned"
        };
        item.SourceInput = ResolveSourceInput(item);
        await EnsureItemPreparedForDraftAsync(item, instaSettings, ct);
        item.UpdatedAt = DateTimeOffset.UtcNow;
        await _calendarStore.SaveAsync(item, ct);
        return item;
    }

    public async Task<ContentCalendarRunSummary> ProcessDueAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var settings = await _settingsStore.GetAsync(ct);
        var instaSettings = settings.InstagramPosts ?? new InstagramPostSettings();
        var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
        var calendarSettings = settings.ContentCalendar ?? new ContentCalendarSettings();
        var maxAttempts = Math.Clamp(calendarSettings.MaxAttempts, 1, 10);

        var items = await _calendarStore.ListAsync(ct);
        var due = items
            .Where(x =>
                x.ScheduledAt <= now &&
                string.Equals(x.Status, "planned", StringComparison.OrdinalIgnoreCase) &&
                x.Attempts < maxAttempts)
            .OrderBy(x => x.ScheduledAt)
            .ToList();

        var processed = 0;
        var published = 0;
        var draftsCreated = 0;
        var failed = 0;

        foreach (var item in due)
        {
            ct.ThrowIfCancellationRequested();
            item.Attempts++;
            item.LastAttemptAt = now;
            item.UpdatedAt = DateTimeOffset.UtcNow;

            try
            {
                await EnsureItemPreparedForDraftAsync(item, instaSettings, ct);
                if (string.IsNullOrWhiteSpace(item.GeneratedCaption))
                {
                    throw new InvalidOperationException("Nao foi possivel gerar legenda para o item.");
                }

                if (string.IsNullOrWhiteSpace(item.MediaUrl))
                {
                    throw new InvalidOperationException("Nao foi possivel identificar uma imagem para o item.");
                }

                var draft = BuildDraftFromItem(item);
                await _publishStore.SaveAsync(draft, ct);
                draftsCreated++;

                item.DraftId = draft.Id;
                item.Error = null;
                item.Status = "draft_created";
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "calendar_draft_created",
                    Success = true,
                    DraftId = draft.Id,
                    Details = $"calendarItem={item.Id}"
                }, ct);

                if (item.AutoPublish)
                {
                    var publishResult = await PublishDraftSimpleAsync(draft, publishSettings, ct);
                    draft.Status = publishResult.Success ? "published" : "failed";
                    draft.MediaId = publishResult.MediaId;
                    draft.Error = publishResult.Success ? null : publishResult.Error;
                    await _publishStore.UpdateAsync(draft, ct);
                    await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                    {
                        Action = "calendar_publish",
                        Success = publishResult.Success,
                        DraftId = draft.Id,
                        MediaId = publishResult.MediaId,
                        Error = publishResult.Error,
                        Details = $"calendarItem={item.Id}"
                    }, ct);

                    if (publishResult.Success)
                    {
                        published++;
                        item.Status = "published";
                        item.PublishedMediaId = publishResult.MediaId;
                        item.Error = null;
                    }
                    else
                    {
                        failed++;
                        item.Status = "failed";
                        item.Error = publishResult.Error;
                    }
                }

                processed++;
            }
            catch (Exception ex)
            {
                failed++;
                item.Status = "failed";
                item.Error = ex.Message;
                _logger.LogWarning(ex, "Calendar processing failed for item {ItemId}", item.Id);
            }
            finally
            {
                item.UpdatedAt = DateTimeOffset.UtcNow;
                await _calendarStore.SaveAsync(item, ct);
            }
        }

        return new ContentCalendarRunSummary(due.Count, processed, published, draftsCreated, failed);
    }

    private async Task EnsureItemPreparedForDraftAsync(ContentCalendarItem item, InstagramPostSettings instaSettings, CancellationToken ct)
    {
        item.SourceInput = ResolveSourceInput(item);
        item.Keyword = NormalizeKeyword(item.Keyword);
        item.Hashtags = NormalizeHashtags(item.Hashtags);

        if (string.IsNullOrWhiteSpace(item.GeneratedCaption))
        {
            var context = BuildOfferContextForAi(item);
            var aiText = await _instagramComposer.BuildAsync(item.SourceInput, context, instaSettings, ct);
            item.GeneratedCaption = (aiText ?? string.Empty).Trim();
        }

        if (string.IsNullOrWhiteSpace(item.Hashtags))
        {
            item.Hashtags = ExtractHashtags(item.GeneratedCaption);
        }

        if (string.IsNullOrWhiteSpace(item.OfferUrl))
        {
            item.OfferUrl = ExtractFirstUrl(item.SourceInput)
                            ?? ExtractFirstUrl(item.GeneratedCaption)
                            ?? string.Empty;
        }

        if (string.IsNullOrWhiteSpace(item.Keyword) && !string.IsNullOrWhiteSpace(item.OfferUrl))
        {
            item.Keyword = BuildKeywordFromSource(item.SourceInput);
        }

        if (string.IsNullOrWhiteSpace(item.MediaUrl))
        {
            item.MediaUrl = ResolveMediaUrl(item);
        }

        if (string.IsNullOrWhiteSpace(item.MediaUrl))
        {
            var candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(item.OfferUrl))
            {
                candidates.Add(item.OfferUrl);
            }

            if (!string.IsNullOrWhiteSpace(item.ReferenceUrl))
            {
                candidates.Add(item.ReferenceUrl);
            }

            foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var meta = await _instagramMetaService.GetMetaAsync(candidate, ct);
                    var image = meta.Images
                        .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x) && !x.EndsWith(".webp", StringComparison.OrdinalIgnoreCase));
                    if (!string.IsNullOrWhiteSpace(image))
                    {
                        item.MediaUrl = image;
                        break;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Could not load metadata for calendar item link {Link}", candidate);
                }
            }
        }
    }

    private static string ResolveMediaUrl(ContentCalendarItem item)
    {
        var options = new[]
        {
            item.MediaUrl,
            item.ReferenceMediaUrl
        };

        foreach (var option in options)
        {
            if (string.IsNullOrWhiteSpace(option))
            {
                continue;
            }

            if (Uri.TryCreate(option.Trim(), UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            {
                return option.Trim();
            }
        }

        return string.Empty;
    }

    private static string ResolveSourceInput(ContentCalendarItem item)
    {
        var candidates = new[]
        {
            item.SourceInput,
            item.OfferUrl,
            item.ReferenceUrl,
            item.ReferenceCaption
        };

        foreach (var candidate in candidates)
        {
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                return candidate.Trim();
            }
        }

        return "Produto em destaque";
    }

    private static string BuildOfferContextForAi(ContentCalendarItem item)
    {
        var sb = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(item.OfferContext))
        {
            sb.AppendLine(item.OfferContext.Trim());
        }

        if (!string.IsNullOrWhiteSpace(item.ReferenceCaption))
        {
            sb.AppendLine("Referencia para inspiracao (nao copiar literalmente):");
            sb.AppendLine(item.ReferenceCaption.Trim());
        }

        if (!string.IsNullOrWhiteSpace(item.ReferenceUrl))
        {
            sb.AppendLine($"Link de referencia: {item.ReferenceUrl.Trim()}");
        }

        return sb.ToString().Trim();
    }

    private static InstagramPublishDraft BuildDraftFromItem(ContentCalendarItem item)
    {
        var caption = NormalizeCaption(item.GeneratedCaption, item.OfferUrl, item.Keyword);
        var hashtags = string.IsNullOrWhiteSpace(item.Hashtags) ? ExtractHashtags(caption) : item.Hashtags;
        var imageUrls = new List<string>();
        if (!string.IsNullOrWhiteSpace(item.MediaUrl))
        {
            imageUrls.Add(item.MediaUrl.Trim());
        }

        var ctas = new List<InstagramCtaOption>();
        if (!string.IsNullOrWhiteSpace(item.OfferUrl))
        {
            ctas.Add(new InstagramCtaOption
            {
                Keyword = string.IsNullOrWhiteSpace(item.Keyword) ? "LINK" : item.Keyword,
                Link = item.OfferUrl.Trim()
            });
        }

        return new InstagramPublishDraft
        {
            PostType = NormalizePostType(item.PostType),
            ProductName = BuildProductName(item.SourceInput),
            Caption = caption,
            CaptionOptions = new List<string> { caption },
            SelectedCaptionIndex = 1,
            Hashtags = hashtags,
            ImageUrls = imageUrls,
            Ctas = ctas
        };
    }

    private async Task<(bool Success, string? MediaId, string? Error)> PublishDraftSimpleAsync(
        InstagramPublishDraft draft,
        InstagramPublishSettings settings,
        CancellationToken ct)
    {
        if (!settings.Enabled)
        {
            return (false, null, "Publicacao Instagram desativada.");
        }

        if (string.IsNullOrWhiteSpace(settings.AccessToken) || settings.AccessToken == "********")
        {
            return (false, null, "Access token do Instagram nao configurado.");
        }

        if (string.IsNullOrWhiteSpace(settings.InstagramUserId))
        {
            return (false, null, "Instagram user id nao configurado.");
        }

        var mediaUrl = draft.ImageUrls.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();
        if (string.IsNullOrWhiteSpace(mediaUrl))
        {
            return (false, null, "Sem imagem para publicacao.");
        }

        if (IsVideoUrl(mediaUrl))
        {
            return (false, null, "Publicacao automatica de video ainda nao suportada no calendario.");
        }

        var baseUrl = string.IsNullOrWhiteSpace(settings.GraphBaseUrl)
            ? "https://graph.facebook.com/v19.0"
            : settings.GraphBaseUrl.TrimEnd('/');
        var client = _httpClientFactory.CreateClient("default");
        var createUrl = $"{baseUrl}/{settings.InstagramUserId}/media";
        var createParams = new Dictionary<string, string>
        {
            ["access_token"] = settings.AccessToken!,
            ["image_url"] = mediaUrl
        };

        var postType = NormalizePostType(draft.PostType);
        if (postType == "story")
        {
            createParams["media_type"] = "STORIES";
        }
        else
        {
            var caption = BuildCaptionWithHashtags(draft.Caption, draft.Hashtags);
            if (!string.IsNullOrWhiteSpace(caption))
            {
                createParams["caption"] = caption;
            }
        }

        using var createResp = await client.PostAsync(createUrl, new FormUrlEncodedContent(createParams), ct);
        var createBody = await createResp.Content.ReadAsStringAsync(ct);
        if (!createResp.IsSuccessStatusCode)
        {
            return (false, null, $"Falha ao criar container: {TrimError(createBody)}");
        }

        var creationId = ExtractIdFromGraphJson(createBody);
        if (string.IsNullOrWhiteSpace(creationId))
        {
            return (false, null, "Falha ao obter creation_id do Instagram.");
        }

        var publishUrl = $"{baseUrl}/{settings.InstagramUserId}/media_publish";
        using var publishResp = await client.PostAsync(
            publishUrl,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["access_token"] = settings.AccessToken!,
                ["creation_id"] = creationId
            }),
            ct);
        var publishBody = await publishResp.Content.ReadAsStringAsync(ct);
        if (!publishResp.IsSuccessStatusCode)
        {
            return (false, null, $"Falha ao publicar: {TrimError(publishBody)}");
        }

        var mediaId = ExtractIdFromGraphJson(publishBody);
        return (true, mediaId, null);
    }

    private static string BuildCaptionWithHashtags(string? caption, string? hashtags)
    {
        var c = (caption ?? string.Empty).Trim();
        var h = (hashtags ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(h))
        {
            return c;
        }

        if (string.IsNullOrWhiteSpace(c))
        {
            return h;
        }

        return $"{c}\n\n{h}";
    }

    private static string NormalizePostType(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "feed";
        }

        var normalized = value.Trim().ToLowerInvariant();
        return normalized.StartsWith("story", StringComparison.Ordinal) ? "story" : "feed";
    }

    private static string BuildProductName(string sourceInput)
    {
        var input = (sourceInput ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            return "Produto em destaque";
        }

        var noUrl = UrlRegex.Replace(input, " ").Trim();
        if (!string.IsNullOrWhiteSpace(noUrl))
        {
            return noUrl.Length <= 120 ? noUrl : noUrl[..120].TrimEnd();
        }

        return "Produto em destaque";
    }

    private static string NormalizeCaption(string text, string? offerUrl, string? keyword)
    {
        var caption = (text ?? string.Empty).Trim();
        if (caption.StartsWith("=== OPENAI ===", StringComparison.OrdinalIgnoreCase) ||
            caption.StartsWith("=== GEMINI ===", StringComparison.OrdinalIgnoreCase))
        {
            caption = caption.Replace("=== OPENAI ===", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("=== GEMINI ===", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Trim();
        }

        if (caption.Length > 2200)
        {
            caption = caption[..2200].TrimEnd() + "...";
        }

        if (!string.IsNullOrWhiteSpace(offerUrl) &&
            !string.IsNullOrWhiteSpace(keyword) &&
            !caption.Contains(keyword, StringComparison.OrdinalIgnoreCase))
        {
            caption = $"{caption}\n\nComente \"{keyword}\" para receber o link.";
        }

        return caption;
    }

    private static string ExtractHashtags(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        return string.Join(' ',
            HashtagRegex.Matches(text)
                .Select(x => x.Value.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(15));
    }

    private static string NormalizeHashtags(string? hashtags)
    {
        var value = (hashtags ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return string.Join(' ',
            value.Split([' ', '\n', '\r', '\t', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => x.StartsWith('#') ? x : $"#{x}")
                .Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static string NormalizeKeyword(string? keyword)
    {
        var value = (keyword ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var cleaned = Regex.Replace(value.ToUpperInvariant(), @"[^A-Z0-9]", string.Empty);
        return cleaned.Length <= 18 ? cleaned : cleaned[..18];
    }

    private static string BuildKeywordFromSource(string? source)
    {
        var baseName = BuildProductName(source ?? string.Empty);
        var token = Regex.Replace(baseName.ToUpperInvariant(), @"[^A-Z0-9]", string.Empty);
        if (string.IsNullOrWhiteSpace(token))
        {
            return "LINK";
        }

        return token.Length <= 12 ? token : token[..12];
    }

    private static string? ExtractFirstUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = UrlRegex.Match(text);
        return match.Success ? match.Value.Trim() : null;
    }

    private static string ExtractIdFromGraphJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return string.Empty;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("id", out var idNode) && idNode.ValueKind == JsonValueKind.String)
            {
                return idNode.GetString() ?? string.Empty;
            }
        }
        catch
        {
            return string.Empty;
        }

        return string.Empty;
    }

    private static string TrimError(string? text)
    {
        var value = (text ?? string.Empty).Trim();
        if (value.Length <= 240)
        {
            return value;
        }

        return value[..240] + "...";
    }

    private static bool IsVideoUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return false;
        }

        var clean = url.ToLowerInvariant();
        return clean.Contains(".mp4", StringComparison.Ordinal) ||
               clean.Contains(".mov", StringComparison.Ordinal) ||
               clean.Contains(".m4v", StringComparison.Ordinal) ||
               clean.Contains(".webm", StringComparison.Ordinal);
    }
}
