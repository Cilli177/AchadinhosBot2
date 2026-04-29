using System.Runtime.Versioning;
using System.Security.Cryptography;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Processing;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Media;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

internal static class InstagramWorkflowSupport
{
    public static List<int> SanitizeSelectedIndexes(IEnumerable<int>? indexes, int maxCount)
    {
        if (indexes is null || maxCount <= 0)
        {
            return new List<int>();
        }

        return indexes
            .Where(i => i >= 1 && i <= maxCount)
            .Distinct()
            .OrderBy(i => i)
            .ToList();
    }

    public static List<string> ResolveSelectedImageUrls(InstagramPublishDraft draft)
    {
        var allImages = (draft.ImageUrls ?? new List<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToList();
        if (allImages.Count == 0)
        {
            return new List<string>();
        }

        var selectedIndexes = SanitizeSelectedIndexes(draft.SelectedImageIndexes, allImages.Count);
        if (selectedIndexes.Count == 0)
        {
            return allImages.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        return selectedIndexes
            .Select(index => allImages[index - 1])
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static string NormalizePostType(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "feed";
        }

        var normalized = value.Trim().ToLowerInvariant();
        if (normalized.StartsWith("story", StringComparison.OrdinalIgnoreCase) || normalized == "stories")
        {
            return "story";
        }

        if (normalized.StartsWith("reel", StringComparison.OrdinalIgnoreCase))
        {
            return "reel";
        }

        return "feed";
    }

    public static string BuildCaption(string caption, string hashtags, IReadOnlyCollection<InstagramCtaOption>? ctas = null)
    {
        caption = FormatCaptionForReadability(caption);
        caption = EnsureCaptionContainsCta(caption, ctas ?? Array.Empty<InstagramCtaOption>());
        caption = EnsureEngagementHook(caption);

        var normalizedHashtags = NormalizeHashtags(hashtags, caption);
        var finalCaption = string.Join("\n\n", new[] { caption.Trim(), normalizedHashtags }.Where(x => !string.IsNullOrWhiteSpace(x)));
        if (finalCaption.Length > 2200)
        {
            finalCaption = finalCaption[..2200].TrimEnd() + "...";
        }

        return finalCaption.Trim();
    }

    public static string PrepareCatalogCaption(string caption)
    {
        var normalized = RemoveUrls(FormatCaptionForReadability(caption));
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return "Acesse a bio e entre no catalogo para ver este produto.";
        }

        if (Regex.IsMatch(normalized, @"\b(bio|catalogo|catálogo)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            return normalized.Trim();
        }

        return $"{normalized.Trim()}\n\nAcesse a bio e entre no catalogo para ver este produto.";
    }

    public static string BuildInstagramCaption(string? caption, string? productName, bool sendToCatalog)
    {
        var normalized = RemoveUrls(FormatCaptionForReadability(caption));
        if (string.IsNullOrWhiteSpace(normalized))
        {
            normalized = !string.IsNullOrWhiteSpace(productName)
                ? $"ALERTA: {productName!.Trim()}\n\nUm achado que chama atencao de verdade."
                : "ALERTA: Achado em destaque\n\nUm produto pronto para chamar atencao e gerar clique.";
        }

        normalized = MakeOpeningMoreVibrant(normalized, productName);

        if (sendToCatalog)
        {
            normalized = MakeOpeningMorePremium(normalized, productName);
            return PrepareCatalogCaption(normalized);
        }

        if (!Regex.IsMatch(normalized, @"\b(bio|catalogo)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            normalized = $"{normalized.Trim()}\n\nAcesse a bio e entre no catalogo para ver este produto.";
        }

        return normalized.Trim();
    }

    public static string BuildWhatsAppCaption(
        string? caption,
        string? productName,
        string? offerUrl,
        string? currentPrice = null,
        string? previousPrice = null,
        int? discountPercent = null)
    {
        var title = FormatCaptionForReadability(productName);
        if (string.IsNullOrWhiteSpace(title))
        {
            title = "Oferta do dia";
        }

        var normalizedCaption = RemoveUrls(FormatCaptionForReadability(caption));
        var hasCurrentPrice = !string.IsNullOrWhiteSpace(currentPrice);
        var hasPreviousPrice = !string.IsNullOrWhiteSpace(previousPrice);
        var pricesAreEqual = hasCurrentPrice &&
            hasPreviousPrice &&
            string.Equals(NormalizePriceForComparison(currentPrice), NormalizePriceForComparison(previousPrice), StringComparison.OrdinalIgnoreCase);
        var builder = new StringBuilder();
        builder.AppendLine("🔥 ACHADO FORTE DO REI DAS OFERTAS");
        builder.AppendLine();
        builder.AppendLine($"🛍️ {title.Trim()}");

        if (hasCurrentPrice)
        {
            builder.AppendLine($"💰 Por: {currentPrice!.Trim()}");
        }

        if (hasPreviousPrice && !pricesAreEqual)
        {
            builder.AppendLine($"🏷️ De: {previousPrice!.Trim()}");
        }

        if (discountPercent is > 0 && !pricesAreEqual)
        {
            builder.AppendLine($"⚡ Desconto aproximado: {discountPercent.Value}%");
        }

        if (!string.IsNullOrWhiteSpace(normalizedCaption))
        {
            builder.AppendLine();
            builder.AppendLine(normalizedCaption.Length > 180 ? normalizedCaption[..180].TrimEnd() + "..." : normalizedCaption.Trim());
        }

        builder.AppendLine();
        builder.AppendLine("🚨 Oferta boa costuma mudar rápido. Vale conferir agora.");

        if (!string.IsNullOrWhiteSpace(offerUrl))
        {
            builder.AppendLine();
            builder.AppendLine("👉 Pegar oferta:");
            builder.AppendLine(offerUrl.Trim());
        }

        return builder.ToString().Trim();
    }

    private static string NormalizePriceForComparison(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return Regex.Replace(value, @"[^\d,\.]", string.Empty, RegexOptions.CultureInvariant).Trim('0', '.', ',');
    }

    public static string FormatCaptionForReadability(string? caption)
    {
        if (string.IsNullOrWhiteSpace(caption))
        {
            return string.Empty;
        }

        var normalized = caption.Replace("\r", string.Empty).Trim();
        normalized = Regex.Replace(normalized, @"\\n", "\n", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"[ \t]+", " ", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"\n{3,}", "\n\n", RegexOptions.CultureInvariant);

        if (!normalized.Contains('\n'))
        {
            var sentences = Regex.Split(normalized, @"(?<=[.!?])\s+", RegexOptions.CultureInvariant)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToList();
            if (sentences.Count > 1)
            {
                normalized = string.Join("\n\n", sentences);
            }
        }

        var lines = normalized.Split('\n', StringSplitOptions.None)
            .Select(line => line.Trim())
            .ToList();

        return string.Join('\n', lines).Trim();
    }

    private static string MakeOpeningMoreVibrant(string caption, string? productName)
    {
        var normalized = caption.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return normalized;
        }

        if (!Regex.IsMatch(normalized, @"^(ALERTA:|OFERTA:|ACHADO:)", RegexOptions.CultureInvariant))
        {
            normalized = $"ALERTA: {normalized}";
        }

        if (!string.IsNullOrWhiteSpace(productName) &&
            !normalized.Contains(productName.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            normalized = $"{normalized}\n\n{productName.Trim()}";
        }

        return normalized.Trim();
    }

    private static string MakeOpeningMorePremium(string caption, string? productName)
    {
        var normalized = caption.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return normalized;
        }

        normalized = Regex.Replace(
            normalized,
            @"^(ALERTA|OFERTA|ACHADO)\s*:\s*",
            string.Empty,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        normalized = Regex.Replace(
            normalized,
            @"^Todo dia a mesma história:\s*",
            "Quando a rotina da cozinha pede mais leveza, vale olhar este achado: ",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        normalized = normalized
            .Replace("😩", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("😤", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Trim();

        if (!string.IsNullOrWhiteSpace(productName) &&
            !normalized.Contains(productName.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            normalized = $"{normalized}\n\n{productName.Trim()}";
        }

        return normalized.Trim();
    }

    public static bool IsMediaTypeError(string? error)
    {
        if (string.IsNullOrWhiteSpace(error))
        {
            return false;
        }

        return error.Contains("Only photo or video can be accepted as media type", StringComparison.OrdinalIgnoreCase)
               || error.Contains("image format is not supported", StringComparison.OrdinalIgnoreCase)
               || error.Contains("code 9004", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsLikelyWebpUrl(string? url)
    {
        return !string.IsNullOrWhiteSpace(url)
               && Regex.IsMatch(url, @"\.webp(\?|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static async Task<List<string>> NormalizeInstagramImagesAsync(
        IHttpClientFactory httpClientFactory,
        IMediaStore mediaStore,
        string? publicBaseUrl,
        string postType,
        List<string> imageUrls,
        CancellationToken cancellationToken)
    {
        var results = new List<string>();
        if (imageUrls.Count == 0 || string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            return results;
        }

        var client = httpClientFactory.CreateClient("default");
        foreach (var url in imageUrls.Take(10))
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                continue;
            }

            try
            {
                using var request = BuildImageFetchRequest(uri);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                if (bytes.Length == 0)
                {
                    continue;
                }

                var normalizedBytes = NormalizeImageBytes(bytes, postType);
                if (normalizedBytes is null)
                {
                    continue;
                }

                var mediaId = mediaStore.Add(normalizedBytes, "image/jpeg", TimeSpan.FromHours(24));
                results.Add(BuildPublicMediaUrl(publicBaseUrl, mediaId));
            }
            catch
            {
            }
        }

        return results;
    }

    public static IEnumerable<InstagramCommentPending> ExtractComments(string json)
    {
        var list = new List<InstagramCommentPending>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("entry", out var entries) || entries.ValueKind != JsonValueKind.Array)
            {
                return list;
            }

            foreach (var entry in entries.EnumerateArray())
            {
                if (!entry.TryGetProperty("changes", out var changes) || changes.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var change in changes.EnumerateArray())
                {
                    var field = GetString(change, "field");
                    if (!string.Equals(field, "comments", StringComparison.OrdinalIgnoreCase) ||
                        !change.TryGetProperty("value", out var value))
                    {
                        continue;
                    }

                    var mediaId = string.Empty;
                    if (value.TryGetProperty("media", out var mediaNode))
                    {
                        mediaId = GetString(mediaNode, "id") ?? string.Empty;
                    }

                    if (string.IsNullOrWhiteSpace(mediaId))
                    {
                        mediaId = GetString(value, "media_id") ?? string.Empty;
                    }

                    string? fromId = null;
                    var from = string.Empty;
                    if (value.TryGetProperty("from", out var fromNode))
                    {
                        from = GetString(fromNode, "username", "name") ?? string.Empty;
                        fromId = GetString(fromNode, "id");
                    }

                    var commentId = GetString(value, "id", "comment_id") ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(commentId))
                    {
                        continue;
                    }

                    list.Add(new InstagramCommentPending
                    {
                        CommentId = commentId,
                        MediaId = mediaId,
                        Text = GetString(value, "text", "message") ?? string.Empty,
                        From = from,
                        FromId = fromId
                    });
                }
            }
        }
        catch
        {
        }

        return list;
    }

    public static IEnumerable<InstagramIncomingDirectMessage> ExtractDirectMessages(string json)
    {
        var list = new List<InstagramIncomingDirectMessage>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("entry", out var entries) || entries.ValueKind != JsonValueKind.Array)
            {
                return list;
            }

            foreach (var entry in entries.EnumerateArray())
            {
                if (entry.TryGetProperty("messaging", out var messaging) && messaging.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in messaging.EnumerateArray())
                    {
                        var fromId = item.TryGetProperty("sender", out var senderNode) ? GetString(senderNode, "id") ?? string.Empty : string.Empty;
                        var toId = item.TryGetProperty("recipient", out var recipientNode) ? GetString(recipientNode, "id") : null;
                        var text = string.Empty;
                        var messageId = string.Empty;
                        var isEcho = false;
                        if (item.TryGetProperty("message", out var messageNode))
                        {
                            text = GetString(messageNode, "text", "body") ?? string.Empty;
                            messageId = GetString(messageNode, "mid", "id") ?? string.Empty;
                            isEcho = GetBool(messageNode, "is_echo");
                        }

                        if (!string.IsNullOrWhiteSpace(fromId) && !string.IsNullOrWhiteSpace(text))
                        {
                            list.Add(new InstagramIncomingDirectMessage(string.IsNullOrWhiteSpace(messageId) ? null : messageId, fromId, toId, text, isEcho));
                        }
                    }
                }

                if (!entry.TryGetProperty("changes", out var changes) || changes.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var change in changes.EnumerateArray())
                {
                    if (!string.Equals(GetString(change, "field"), "messages", StringComparison.OrdinalIgnoreCase) ||
                        !change.TryGetProperty("value", out var value))
                    {
                        continue;
                    }

                    if (value.TryGetProperty("messages", out var messagesArray) && messagesArray.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var message in messagesArray.EnumerateArray())
                        {
                            var text = GetString(message, "text", "body", "message") ?? string.Empty;
                            var messageId = GetString(message, "id", "mid");
                            var fromId = GetString(value, "from", "sender_id") ?? GetString(message, "from") ?? string.Empty;
                            var toId = GetString(value, "to", "recipient_id") ?? GetString(message, "to");
                            var isEcho = GetBool(message, "is_echo");
                            if (!string.IsNullOrWhiteSpace(fromId) && !string.IsNullOrWhiteSpace(text))
                            {
                                list.Add(new InstagramIncomingDirectMessage(messageId, fromId, toId, text, isEcho));
                            }
                        }

                        continue;
                    }

                    var singleText = value.TryGetProperty("message", out var singleMessageNode)
                        ? singleMessageNode.ValueKind == JsonValueKind.String
                            ? singleMessageNode.GetString() ?? string.Empty
                            : GetString(singleMessageNode, "text", "body") ?? string.Empty
                        : GetString(value, "text", "body") ?? string.Empty;
                    var singleMessageId = GetString(value, "id", "mid");
                    var singleFromId = value.TryGetProperty("from", out var fromNode)
                        ? GetString(fromNode, "id") ?? string.Empty
                        : GetString(value, "from", "sender_id") ?? string.Empty;
                    var singleToId = value.TryGetProperty("to", out var toNode)
                        ? GetString(toNode, "id")
                        : GetString(value, "to", "recipient_id");
                    var singleIsEcho = GetBool(value, "is_echo");
                    if (!string.IsNullOrWhiteSpace(singleFromId) && !string.IsNullOrWhiteSpace(singleText))
                    {
                        list.Add(new InstagramIncomingDirectMessage(singleMessageId, singleFromId, singleToId, singleText, singleIsEcho));
                    }
                }
            }
        }
        catch
        {
        }

        return list;
    }

    public static async Task<InstagramPublishDraft?> FindDraftByMediaIdAsync(IInstagramPublishStore store, string mediaId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(mediaId))
        {
            return null;
        }

        var items = await store.ListAsync(cancellationToken);
        return items.FirstOrDefault(x => string.Equals(x.MediaId, mediaId, StringComparison.OrdinalIgnoreCase));
    }

    public static InstagramCtaResolution ResolveCtaReply(InstagramPublishDraft? draft, InstagramPublishSettings settings, string commentText)
    {
        var defaultReply = settings.ReplyNoMatchTemplate ?? string.Empty;
        if (draft is null)
        {
            return new InstagramCtaResolution(defaultReply, false, null, null);
        }

        var effectiveCtas = BuildEffectiveDraftCtas(draft);
        if (effectiveCtas.Count == 0)
        {
            return new InstagramCtaResolution(defaultReply, false, null, null);
        }

        var match = effectiveCtas.FirstOrDefault(c =>
            !string.IsNullOrWhiteSpace(c.Keyword) &&
            commentText.Contains(c.Keyword, StringComparison.OrdinalIgnoreCase));
        var hasKeywordMatch = match is not null;

        if (match is null && !settings.AutoReplyOnlyOnKeywordMatch && effectiveCtas.Count == 1)
        {
            match = effectiveCtas[0];
        }

        if (match is null)
        {
            return new InstagramCtaResolution(defaultReply, false, null, null);
        }

        var template = settings.ReplyTemplate ?? "Aqui esta o link: {link}";
        var reply = template.Replace("{link}", match.Link ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{keyword}", match.Keyword ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        return new InstagramCtaResolution(reply, hasKeywordMatch, match.Keyword, match.Link);
    }

    public static async Task<InstagramCtaResolution> ResolveDmKeywordReplyAsync(
        IInstagramPublishStore publishStore,
        InstagramPublishSettings settings,
        string messageText,
        CancellationToken cancellationToken)
    {
        var defaultReply = settings.ReplyNoMatchTemplate ?? string.Empty;
        if (string.IsNullOrWhiteSpace(messageText))
        {
            return new InstagramCtaResolution(defaultReply, false, null, null);
        }

        var drafts = await publishStore.ListAsync(cancellationToken);
        var ordered = drafts
            .OrderByDescending(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(d => d.CreatedAt);

        foreach (var draft in ordered)
        {
            var match = BuildEffectiveDraftCtas(draft).FirstOrDefault(c =>
                !string.IsNullOrWhiteSpace(c.Keyword) &&
                messageText.Contains(c.Keyword, StringComparison.OrdinalIgnoreCase));
            if (match is null)
            {
                continue;
            }

            var template = settings.ReplyTemplate ?? "Aqui esta o link: {link}";
            var reply = template.Replace("{link}", match.Link ?? string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("{keyword}", match.Keyword ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            return new InstagramCtaResolution(reply, true, match.Keyword, match.Link);
        }

        return new InstagramCtaResolution(defaultReply, false, null, null);
    }

    public static string BuildCommentDmMessage(InstagramPublishDraft? draft, InstagramPublishSettings settings, InstagramCommentPending comment, InstagramCtaResolution cta)
        => BuildDmMessageTemplate(draft?.AutoReplyMessage, settings, cta.Link, cta.Keyword, comment.From, comment.Text);

    public static string BuildInboundDmMessage(InstagramPublishSettings settings, InstagramCtaResolution cta, string inboundText)
        => cta.HasKeywordMatch
            ? BuildDmMessageTemplate(null, settings, cta.Link, cta.Keyword, string.Empty, inboundText)
            : cta.Reply;

    private static string BuildDmMessageTemplate(string? preferredTemplate, InstagramPublishSettings settings, string? link, string? keyword, string? name, string? commentText)
    {
        var template = !string.IsNullOrWhiteSpace(preferredTemplate)
            ? preferredTemplate
            : string.IsNullOrWhiteSpace(settings.DmTemplate)
            ? "Oi {name}! Aqui esta seu link: {link}"
            : settings.DmTemplate;

        return template.Replace("{link}", link ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{keyword}", keyword ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{name}", name ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{comment}", commentText ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    private static List<InstagramCtaOption> BuildEffectiveDraftCtas(InstagramPublishDraft draft)
    {
        var captions = new List<string>();
        if (!string.IsNullOrWhiteSpace(draft.Caption))
        {
            captions.Add(draft.Caption);
        }

        captions.AddRange((draft.CaptionOptions ?? new List<string>()).Where(x => !string.IsNullOrWhiteSpace(x)));
        var fallbackLink = FirstNonEmpty(
            draft.AutoReplyLink,
            draft.Ctas?.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link))?.Link,
            ExtractFirstUrl(draft.Caption),
            ExtractFirstUrl(string.Join(" ", captions)));

        var map = new Dictionary<string, InstagramCtaOption>(StringComparer.OrdinalIgnoreCase);
        foreach (var cta in draft.Ctas ?? new List<InstagramCtaOption>())
        {
            foreach (var keyword in NormalizeKeywords(new[] { cta.Keyword }))
            {
                map[keyword] = new InstagramCtaOption
                {
                    Keyword = keyword,
                    Link = string.IsNullOrWhiteSpace(cta.Link) ? (fallbackLink ?? string.Empty) : cta.Link.Trim()
                };
            }
        }

        if (draft.AutoReplyEnabled)
        {
            foreach (var keyword in NormalizeKeywords(Regex.Split(draft.AutoReplyKeyword ?? string.Empty, @"[\s,;|/]+", RegexOptions.CultureInvariant)))
            {
                map[keyword] = new InstagramCtaOption
                {
                    Keyword = keyword,
                    Link = fallbackLink ?? string.Empty
                };
            }
        }

        foreach (var keyword in ExtractCaptionKeywords(captions))
        {
            if (!map.ContainsKey(keyword))
            {
                map[keyword] = new InstagramCtaOption
                {
                    Keyword = keyword,
                    Link = fallbackLink ?? string.Empty
                };
            }
        }

        return map.Values
            .Where(x => !string.IsNullOrWhiteSpace(x.Keyword) && !string.IsNullOrWhiteSpace(x.Link))
            .ToList();
    }

    private static IEnumerable<string> NormalizeKeywords(IEnumerable<string?> rawKeywords)
    {
        return (rawKeywords ?? Array.Empty<string?>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => Regex.Replace(x!.Trim().ToUpperInvariant(), @"[^A-Z0-9À-ÖØ-Þ]+", string.Empty, RegexOptions.CultureInvariant))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(10);
    }

    private static IEnumerable<string> ExtractCaptionKeywords(IEnumerable<string> captions)
    {
        var matches = new List<string>();
        foreach (var caption in captions)
        {
            foreach (Match match in Regex.Matches(
                         caption ?? string.Empty,
                         @"(?:comente|comenta|digite|digita|escreva)\s+[""']?(?<keyword>[A-Za-z0-9À-ÖØ-öø-ÿ_ -]{2,32})[""']?",
                         RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                matches.Add(match.Groups["keyword"].Value);
            }
        }

        return NormalizeKeywords(matches);
    }

    private static string? ExtractFirstUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = Regex.Match(text, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Value.Trim() : null;
    }

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();

    private static string EnsureCaptionContainsCta(string caption, IReadOnlyCollection<InstagramCtaOption> ctas)
    {
        var baseCaption = (caption ?? string.Empty).Trim();
        var primaryKeyword = ctas.Select(c => c.Keyword?.Trim()).FirstOrDefault(k => !string.IsNullOrWhiteSpace(k));
        if (string.IsNullOrWhiteSpace(primaryKeyword))
        {
            return baseCaption;
        }

        var hasKeyword = Regex.IsMatch(baseCaption, $@"\b{Regex.Escape(primaryKeyword)}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (hasKeyword)
        {
            return baseCaption;
        }

        var ctaLine = BuildCtaLine(primaryKeyword, baseCaption);
        return string.IsNullOrWhiteSpace(baseCaption) ? ctaLine : $"{baseCaption}\n\n{ctaLine}";
    }

    private static string BuildCtaLine(string primaryKeyword, string seed)
    {
        var templates = new[]
        {
            "Comente \"{0}\" para receber o link.",
            "Quer o link? Escreva \"{0}\" nos comentarios.",
            "Digita \"{0}\" aqui embaixo que eu te envio o link.",
            "Comenta \"{0}\" e te mando o link completo.",
            "Para receber o link, comente \"{0}\"."
        };

        var idx = ComputeDeterministicIndex($"{primaryKeyword}|{seed}", templates.Length);
        return string.Format(templates[idx], primaryKeyword);
    }

    private static int ComputeDeterministicIndex(string seed, int length)
    {
        if (length <= 0)
        {
            return 0;
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed ?? string.Empty));
        var value = BitConverter.ToInt32(hash, 0) & int.MaxValue;
        return value % length;
    }

    private static string EnsureEngagementHook(string caption)
    {
        var text = (caption ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        var hasHook = Regex.IsMatch(
            text,
            @"\b(comente|comenta|salve|compartilhe|link na bio|direct|dm|chama no direct)\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        return hasHook ? text : $"{text}\n\nSalve este post e compartilhe com quem ama promocoes.";
    }

    private static string RemoveUrls(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        var withoutUrls = Regex.Replace(text, @"https?://\S+", string.Empty, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        withoutUrls = Regex.Replace(withoutUrls, @"\s{2,}", " ", RegexOptions.CultureInvariant);
        withoutUrls = Regex.Replace(withoutUrls, @"\n{3,}", "\n\n", RegexOptions.CultureInvariant);
        return withoutUrls.Trim();
    }

    private static string NormalizeHashtags(string hashtags, string caption)
    {
        static IEnumerable<string> ExtractTags(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                yield break;
            }

            foreach (Match match in Regex.Matches(input, @"#([A-Za-z0-9_À-ÖØ-öø-ÿ]+)", RegexOptions.CultureInvariant))
            {
                var normalized = "#" + match.Groups[1].Value.Trim().TrimStart('#');
                if (normalized.Length > 1)
                {
                    yield return normalized;
                }
            }
        }

        var tags = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var tag in ExtractTags(hashtags).Concat(ExtractTags(caption)))
        {
            if (seen.Add(tag))
            {
                tags.Add(tag);
            }
        }

        foreach (var fallback in new[] { "#achadinhos", "#ofertas", "#promocoes", "#descontos", "#custobeneficio", "#dicadecompra" })
        {
            if (tags.Count >= 5)
            {
                break;
            }

            if (seen.Add(fallback))
            {
                tags.Add(fallback);
            }
        }

        return string.Join(' ', tags.Take(10));
    }

    private static HttpRequestMessage BuildImageFetchRequest(Uri uri)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.ParseAdd("image/avif,image/webp,image/apng,image/*,*/*;q=0.8");
        request.Headers.AcceptLanguage.ParseAdd("pt-BR,pt;q=0.9,en;q=0.8");
        request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true };
        request.Headers.Referrer = new Uri(uri.GetLeftPart(UriPartial.Authority));
        return request;
    }

    private static byte[]? NormalizeImageBytes(byte[] input, string postType)
    {
        return ImageNormalizationSupport.NormalizeForInstagramPublication(input, NormalizePostType(postType));
    }

    private static string BuildPublicMediaUrl(string publicBaseUrl, string mediaId)
    {
        var url = publicBaseUrl.TrimEnd('/') + $"/media/{mediaId}.jpg";
        if (url.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) || url.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase))
        {
            url += "?ngrok-skip-browser-warning=1";
        }

        return url;
    }

    private static string? GetString(JsonElement node, params string[] names)
    {
        foreach (var name in names)
        {
            if (node.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }
        }

        return null;
    }

    private static bool GetBool(JsonElement node, string name)
    {
        if (node.TryGetProperty(name, out var value))
        {
            if (value.ValueKind == JsonValueKind.True)
            {
                return true;
            }

            if (value.ValueKind == JsonValueKind.False)
            {
                return false;
            }
        }

        return false;
    }
}

internal sealed record InstagramIncomingDirectMessage(string? MessageId, string FromId, string? ToId, string Text, bool IsEcho);

internal sealed record InstagramCtaResolution(string Reply, bool HasKeywordMatch, string? Keyword, string? Link);
