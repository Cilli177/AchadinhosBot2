using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Compliance;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class MessageProcessor : IMessageProcessor
{
    private readonly IAffiliateLinkService _affiliateLinkService;
    private const string OfficialWhatsAppDemandGroupId = "120363405661434395@g.us";
    private readonly IConversionLogStore _conversionLogStore;
    private readonly ICouponSelector _couponSelector;
    private readonly ISettingsStore _settingsStore;
    private readonly IMercadoLivreApprovalStore _mercadoLivreApprovalStore;
    private readonly Infrastructure.ProductData.OfficialProductDataService _productDataService;
    private readonly ILogger<MessageProcessor> _logger;

    public MessageProcessor(
        IAffiliateLinkService affiliateLinkService,
        IConversionLogStore conversionLogStore,
        ICouponSelector couponSelector,
        ISettingsStore settingsStore,
        IMercadoLivreApprovalStore mercadoLivreApprovalStore,
        Infrastructure.ProductData.OfficialProductDataService productDataService,
        ILogger<MessageProcessor> logger)
    {
        _affiliateLinkService = affiliateLinkService;
        _conversionLogStore = conversionLogStore;
        _couponSelector = couponSelector;
        _settingsStore = settingsStore;
        _mercadoLivreApprovalStore = mercadoLivreApprovalStore;
        _productDataService = productDataService;
        _logger = logger;
    }

    public async Task<ConversionResult> ProcessAsync(
        string input,
        string source,
        CancellationToken cancellationToken,
        long? originChatId = null,
        long? destinationChatId = null,
        string? originChatRef = null,
        string? destinationChatRef = null,
        string? sourceImageUrl = null)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new ConversionResult(false, null, 0, source);
        }

        var matches = UrlRegex().Matches(input);
        if (matches.Count == 0)
        {
            return new ConversionResult(false, null, 0, source);
        }

        var sw = Stopwatch.StartNew();
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var items = new List<UrlWorkItem>(matches.Count);
        foreach (Match match in matches)
        {
            var cleanedUrl = CleanUrl(match.Value, out var prefix, out var suffix);
            var isBlocked = IsBlockedUrl(cleanedUrl);
            var shouldConvert = !isBlocked && ShouldAttemptAffiliateConversion(cleanedUrl);
            items.Add(new UrlWorkItem(match, cleanedUrl, prefix, suffix, isBlocked, shouldConvert));
        }

        var mercadoLivreUrls = items
            .Where(x => IsMercadoLivreUrl(x.CleanedUrl))
            .Select(x => x.CleanedUrl)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var approvedMercadoLivreUrls = mercadoLivreUrls.Length > 0
            ? await _mercadoLivreApprovalStore.GetApprovedUrlsAsync(mercadoLivreUrls, cancellationToken)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unapprovedMercadoLivreUrls = mercadoLivreUrls
            .Where(x => !approvedMercadoLivreUrls.Contains(NormalizeUrl(x)))
            .ToArray();
        var isAutomaticSource = IsAutomaticSource(source);
        MercadoLivreComplianceSettings? mercadoLivreCompliance = null;

        if (unapprovedMercadoLivreUrls.Length > 0)
        {
            var compliance = settings.MercadoLivreCompliance ?? new MercadoLivreComplianceSettings();
            mercadoLivreCompliance = compliance;
            var reason = EvaluateMercadoLivreCompliance(
                compliance,
                source,
                originChatId,
                destinationChatId,
                originChatRef,
                destinationChatRef);

            if (!string.IsNullOrWhiteSpace(reason))
            {
                if (compliance.RequireManualApproval && isAutomaticSource)
                {
                    await _mercadoLivreApprovalStore.AppendAsync(new MercadoLivrePendingApproval
                    {
                        Source = source,
                        Reason = reason!,
                        OriginalText = input,
                        ExtractedUrls = unapprovedMercadoLivreUrls.ToList(),
                        OriginalImageUrl = sourceImageUrl,
                        OriginChatId = originChatId,
                        DestinationChatId = destinationChatId,
                        OriginChatRef = originChatRef,
                        DestinationChatRef = destinationChatRef
                    }, cancellationToken);
                }

                await _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
                {
                    Source = source,
                    Store = "Mercado Livre",
                    Success = false,
                    Error = reason,
                    OriginalUrl = string.Join(" | ", unapprovedMercadoLivreUrls),
                    ConvertedUrl = string.Empty,
                    OriginChatId = originChatId,
                    DestinationChatId = destinationChatId,
                    OriginChatRef = originChatRef,
                    DestinationChatRef = destinationChatRef,
                    ElapsedMs = sw.ElapsedMilliseconds
                }, cancellationToken);

                _logger.LogWarning(
                    "Compliance Mercado Livre bloqueou processamento. Source={Source} Reason={Reason} Urls={Urls}",
                    source,
                    reason,
                    string.Join(" | ", unapprovedMercadoLivreUrls));

                return new ConversionResult(false, null, 0, source);
            }
        }

        var isOfficialDemandGroup = string.Equals(destinationChatRef, OfficialWhatsAppDemandGroupId, StringComparison.OrdinalIgnoreCase)
            || (destinationChatId.HasValue && string.Equals(destinationChatId.Value.ToString(), OfficialWhatsAppDemandGroupId, StringComparison.OrdinalIgnoreCase));

        var tasks = new Task<AffiliateLinkResult>[items.Count];
        for (var i = 0; i < items.Count; i++)
        {
            tasks[i] = !items[i].ShouldConvert
                ? Task.FromResult(new AffiliateLinkResult(false, null, DetectStore(null, items[i].CleanedUrl), false, null, "Conversao ignorada para URL nao afiliada", false, null))
                : items[i].IsBlocked
                ? Task.FromResult(new AffiliateLinkResult(false, null, "Unknown", false, null, "Link bloqueado", false, null))
                : _affiliateLinkService.ConvertAsync(items[i].CleanedUrl, cancellationToken, source, forceResolution: isOfficialDemandGroup);
        }

        await Task.WhenAll(tasks);

        var detectedMercadoLivreUrls = new HashSet<string>(mercadoLivreUrls, StringComparer.OrdinalIgnoreCase);
        var invalidMercadoLivreUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            if (item.IsBlocked || !item.ShouldConvert)
            {
                continue;
            }

            var result = tasks[i].Result;
            var convertedUrl = result.ConvertedUrl ?? string.Empty;
            var detectedStore = string.IsNullOrWhiteSpace(result.Store)
                ? DetectStore(convertedUrl, item.CleanedUrl)
                : result.Store;
            var detectedAsMercadoLivre =
                IsMercadoLivreUrl(item.CleanedUrl)
                || IsMercadoLivreUrl(convertedUrl)
                || string.Equals(detectedStore, "Mercado Livre", StringComparison.OrdinalIgnoreCase);
            if (!detectedAsMercadoLivre)
            {
                continue;
            }

            detectedMercadoLivreUrls.Add(item.CleanedUrl);
            if (!string.IsNullOrWhiteSpace(result.ConvertedUrl))
            {
                detectedMercadoLivreUrls.Add(result.ConvertedUrl);
            }

            var valid = result.Success && result.IsAffiliated && !string.IsNullOrWhiteSpace(result.ConvertedUrl);
            if (!valid)
            {
                invalidMercadoLivreUrls.Add(item.CleanedUrl);
            }
        }

        if (detectedMercadoLivreUrls.Count > 0 && isAutomaticSource)
        {
            var approvedDetectedUrls = await _mercadoLivreApprovalStore.GetApprovedUrlsAsync(detectedMercadoLivreUrls.ToArray(), cancellationToken);
            var unapprovedDetectedUrls = detectedMercadoLivreUrls
                .Where(x => !approvedDetectedUrls.Contains(NormalizeUrl(x)))
                .ToArray();
            if (unapprovedDetectedUrls.Length > 0)
            {
                var compliance = mercadoLivreCompliance ?? settings.MercadoLivreCompliance ?? new MercadoLivreComplianceSettings();
                var reason = EvaluateMercadoLivreCompliance(
                    compliance,
                    source,
                    originChatId,
                    destinationChatId,
                    originChatRef,
                    destinationChatRef);

                if (!string.IsNullOrWhiteSpace(reason))
                {
                    if (compliance.RequireManualApproval)
                    {
                        await _mercadoLivreApprovalStore.AppendAsync(new MercadoLivrePendingApproval
                        {
                            Source = source,
                            Reason = reason!,
                            OriginalText = input,
                            ExtractedUrls = unapprovedDetectedUrls.ToList(),
                            OriginalImageUrl = sourceImageUrl,
                            OriginChatId = originChatId,
                            DestinationChatId = destinationChatId,
                            OriginChatRef = originChatRef,
                            DestinationChatRef = destinationChatRef
                        }, cancellationToken);
                    }

                    await _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
                    {
                        Source = source,
                        Store = "Mercado Livre",
                        Success = false,
                        Error = reason,
                        OriginalUrl = string.Join(" | ", unapprovedDetectedUrls),
                        ConvertedUrl = string.Empty,
                        OriginChatId = originChatId,
                        DestinationChatId = destinationChatId,
                        OriginChatRef = originChatRef,
                        DestinationChatRef = destinationChatRef,
                        ElapsedMs = sw.ElapsedMilliseconds
                    }, cancellationToken);

                    _logger.LogWarning(
                        "Compliance Mercado Livre (expandido) bloqueou processamento. Source={Source} Reason={Reason} Urls={Urls}",
                        source,
                        reason,
                        string.Join(" | ", unapprovedDetectedUrls));

                    return new ConversionResult(false, null, 0, source);
                }
            }
        }

        if (invalidMercadoLivreUrls.Count > 0 && isAutomaticSource)
        {
            var approvedInvalidUrls = await _mercadoLivreApprovalStore.GetApprovedUrlsAsync(invalidMercadoLivreUrls.ToArray(), cancellationToken);
            var invalidUnapprovedUrls = invalidMercadoLivreUrls
                .Where(x => !approvedInvalidUrls.Contains(NormalizeUrl(x)))
                .ToArray();
            if (invalidUnapprovedUrls.Length > 0)
            {
                var reason = "Verificacao obrigatoria do Mercado Livre falhou. Link nao sera enviado automaticamente.";
                if (mercadoLivreCompliance?.RequireManualApproval ?? true)
                {
                    await _mercadoLivreApprovalStore.AppendAsync(new MercadoLivrePendingApproval
                    {
                        Source = source,
                        Reason = reason,
                        OriginalText = input,
                        ExtractedUrls = invalidUnapprovedUrls.ToList(),
                        OriginalImageUrl = sourceImageUrl,
                        OriginChatId = originChatId,
                        DestinationChatId = destinationChatId,
                        OriginChatRef = originChatRef,
                        DestinationChatRef = destinationChatRef
                    }, cancellationToken);
                }

                await _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
                {
                    Source = source,
                    Store = "Mercado Livre",
                    Success = false,
                    Error = reason,
                    OriginalUrl = string.Join(" | ", invalidUnapprovedUrls),
                    ConvertedUrl = string.Empty,
                    OriginChatId = originChatId,
                    DestinationChatId = destinationChatId,
                    OriginChatRef = originChatRef,
                    DestinationChatRef = destinationChatRef,
                    ElapsedMs = sw.ElapsedMilliseconds
                }, cancellationToken);

                _logger.LogWarning("Bloqueio automatico Mercado Livre por validacao obrigatoria. Source={Source} Urls={Urls}",
                    source,
                    string.Join(" | ", invalidUnapprovedUrls));

                return new ConversionResult(false, null, 0, source);
            }
        }

        var linkIntegrityBlockReason = EvaluateLinkIntegrityGate(settings.LinkIntegrity, source, items, tasks);
        if (!string.IsNullOrWhiteSpace(linkIntegrityBlockReason))
        {
            await _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
            {
                Source = source,
                Store = "Link Integrity",
                Success = false,
                Error = linkIntegrityBlockReason,
                OriginalUrl = string.Join(" | ", items.Select(x => x.CleanedUrl).Distinct(StringComparer.OrdinalIgnoreCase)),
                ConvertedUrl = string.Empty,
                OriginChatId = originChatId,
                DestinationChatId = destinationChatId,
                OriginChatRef = originChatRef,
                DestinationChatRef = destinationChatRef,
                ElapsedMs = sw.ElapsedMilliseconds
            }, cancellationToken);

            _logger.LogWarning("Link Integrity Gate bloqueou processamento. Source={Source} Reason={Reason}", source, linkIntegrityBlockReason);
            return new ConversionResult(false, null, 0, source);
        }

        var sb = new StringBuilder(input.Length + 128);
        var lastIndex = 0;
        var converted = 0;
        var convertedStores = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            sb.Append(input, lastIndex, item.Match.Index - lastIndex);

            if (item.IsBlocked)
            {
                sb.Append(item.Match.Value);
            }
            else if (!item.ShouldConvert)
            {
                // Preserve institutional and non-affiliate URLs exactly as configured.
                sb.Append(item.Match.Value);
            }
            else
            {
                var result = tasks[i].Result;
                if (result.Success && !string.IsNullOrWhiteSpace(result.ConvertedUrl))
                {
                    sb.Append(item.Prefix);
                    sb.Append(result.ConvertedUrl);
                    sb.Append(item.Suffix);
                    converted++;
                    convertedStores.Add(string.IsNullOrWhiteSpace(result.Store) ? DetectStore(result.ConvertedUrl, item.CleanedUrl) : result.Store);
                    _ = _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
                    {
                        Source = source,
                        Store = string.IsNullOrWhiteSpace(result.Store) ? DetectStore(result.ConvertedUrl, item.CleanedUrl) : result.Store,
                        Success = true,
                        IsAffiliated = result.IsAffiliated,
                        ValidationError = result.ValidationError,
                        AffiliateCorrected = result.CorrectionApplied,
                        AffiliateCorrectionNote = result.CorrectionNote,
                        OriginalUrl = item.CleanedUrl,
                        ConvertedUrl = result.ConvertedUrl,
                        OriginChatId = originChatId,
                        DestinationChatId = destinationChatId,
                        OriginChatRef = originChatRef,
                        DestinationChatRef = destinationChatRef,
                        ElapsedMs = sw.ElapsedMilliseconds
                    }, cancellationToken);
                }
                else
                {
                    sb.Append(item.Match.Value);
                    _ = _conversionLogStore.AppendAsync(new Domain.Logs.ConversionLogEntry
                    {
                        Source = source,
                        Store = string.IsNullOrWhiteSpace(result.Store) ? DetectStore(null, item.CleanedUrl) : result.Store,
                        Success = false,
                        Error = result.Error,
                        ValidationError = result.ValidationError,
                        AffiliateCorrected = result.CorrectionApplied,
                        AffiliateCorrectionNote = result.CorrectionNote,
                        OriginalUrl = item.CleanedUrl,
                        ConvertedUrl = string.Empty,
                        OriginChatId = originChatId,
                        DestinationChatId = destinationChatId,
                        OriginChatRef = originChatRef,
                        DestinationChatRef = destinationChatRef,
                        ElapsedMs = sw.ElapsedMilliseconds
                    }, cancellationToken);
                }
            }

            lastIndex = item.Match.Index + item.Match.Length;
        }

        sb.Append(input, lastIndex, input.Length - lastIndex);
        var convertedBodyText = sb.ToString();

        if (converted > 0 && settings.CouponHub.Enabled && settings.CouponHub.AppendToConvertedMessages)
        {
            var couponText = await BuildCouponAppendixAsync(settings, convertedStores, cancellationToken);
            if (!string.IsNullOrWhiteSpace(couponText))
            {
                sb.AppendLine();
                sb.AppendLine();
                sb.Append(couponText);
            }
        }

        if (converted > 0)
        {
            var comparisonText = await BuildConverterSkillAppendixAsync(settings, source, input, convertedBodyText, cancellationToken);
            if (!string.IsNullOrWhiteSpace(comparisonText))
            {
                sb.AppendLine();
                sb.AppendLine();
                sb.Append(comparisonText);
            }
        }

        _logger.LogInformation("Processamento concluído. Source={Source} ConvertedLinks={ConvertedLinks}", source, converted);
        return new ConversionResult(converted > 0, converted > 0 ? sb.ToString() : null, converted, source);
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    private static string CleanUrl(string raw, out string prefix, out string suffix)
    {
        prefix = string.Empty;
        suffix = string.Empty;

        var start = 0;
        var end = raw.Length - 1;

        while (start <= end && IsTrimChar(raw[start]))
        {
            prefix += raw[start];
            start++;
        }

        while (end >= start && IsTrimChar(raw[end]))
        {
            suffix = raw[end] + suffix;
            end--;
        }

        if (start > end)
        {
            return raw;
        }

        return raw[start..(end + 1)];
    }

    private static bool IsTrimChar(char c)
        => c is '"' or '\'' or '`' or '.' or ',' or ';' or ':' or ')' or ']' or '}' or '!' or '?';

    private static readonly string[] BlockedHosts =
    {
        "tidd.ly",
        "natura.com",
        "magazineluiza.com.br",
        "magazineluiza.com",
        "magalu.com"
    };

    private static bool IsBlockedUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        foreach (var blocked in BlockedHosts)
        {
            if (host == blocked || host.EndsWith("." + blocked, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsMercadoLivreUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        return host.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
               || host.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
               || host.Contains("meli.co", StringComparison.OrdinalIgnoreCase)
               || host.Contains("meli.la", StringComparison.OrdinalIgnoreCase);
    }

    private static string? EvaluateMercadoLivreCompliance(
        MercadoLivreComplianceSettings compliance,
        string source,
        long? originChatId,
        long? destinationChatId,
        string? originChatRef,
        string? destinationChatRef)
    {
        if (!compliance.Enabled)
        {
            return null;
        }

        var reasons = new List<string>();
        var isAutomatic = IsAutomaticSource(source);

        if (compliance.EnforceChannelWhitelist && compliance.AllowedChannels.Count > 0)
        {
            var allowed = new HashSet<string>(
                compliance.AllowedChannels
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim()),
                StringComparer.OrdinalIgnoreCase);

            var channels = ExtractChannelRefs(originChatId, destinationChatId, originChatRef, destinationChatRef);
            if (channels.Count == 0 && compliance.BlockWhenChannelUnknown)
            {
                reasons.Add("Canal de origem/destino nao identificado para whitelist do Mercado Livre.");
            }
            else
            {
                var invalid = channels
                    .Where(x => !allowed.Contains(x))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (invalid.Count > 0)
                {
                    reasons.Add($"Canal nao autorizado para Mercado Livre: {string.Join(", ", invalid)}.");
                }
            }
        }

        if (isAutomatic && compliance.RequireManualApproval)
        {
            reasons.Add("Aprovacao manual obrigatoria para links do Mercado Livre.");
        }
        else if (isAutomatic && compliance.BlockAutoFlows)
        {
            reasons.Add("Fluxo automatico bloqueado para links do Mercado Livre.");
        }

        return reasons.Count == 0 ? null : string.Join(" ", reasons);
    }

    private static List<string> ExtractChannelRefs(
        long? originChatId,
        long? destinationChatId,
        string? originChatRef,
        string? destinationChatRef)
    {
        var refs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddCompositeRefs(destinationChatRef, refs);
        AddCompositeRefs(originChatRef, refs);
        if (destinationChatId.HasValue && destinationChatId.Value != 0)
        {
            refs.Add(destinationChatId.Value.ToString());
        }
        if (originChatId.HasValue && originChatId.Value != 0)
        {
            refs.Add(originChatId.Value.ToString());
        }
        return refs.ToList();
    }

    private static void AddCompositeRefs(string? raw, HashSet<string> refs)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        var tokens = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var token in tokens)
        {
            if (!string.IsNullOrWhiteSpace(token))
            {
                refs.Add(token.Trim());
            }
        }
    }

    private static bool IsAutomaticSource(string source)
    {
        var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "playground" => false,
            "mercadolivremanualapproval" => false,
            "manual" => false,
            _ => true
        };
    }

    private string? EvaluateLinkIntegrityGate(
        LinkIntegritySettings integrity,
        string source,
        IReadOnlyList<UrlWorkItem> items,
        IReadOnlyList<Task<AffiliateLinkResult>> tasks)
    {
        if (!integrity.Enabled || !IsAutomaticSource(source))
        {
            return null;
        }

        var enforcedStores = new HashSet<string>(
            (integrity.EnforcedStores ?? new List<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

        var failures = new List<string>();

        for (var i = 0; i < items.Count; i++)
        {
            if (items[i].IsBlocked)
            {
                continue;
            }

            var result = tasks[i].Result;
            var detectedStore = string.IsNullOrWhiteSpace(result.Store) || string.Equals(result.Store, "Unknown", StringComparison.OrdinalIgnoreCase)
                ? DetectStore(result.ConvertedUrl, items[i].CleanedUrl)
                : result.Store;

            var isUnknownStore = string.IsNullOrWhiteSpace(detectedStore) || string.Equals(detectedStore, "Unknown", StringComparison.OrdinalIgnoreCase);
            if (isUnknownStore && integrity.IgnoreUnknownStores)
            {
                continue;
            }

            if (enforcedStores.Count > 0 && !enforcedStores.Contains(detectedStore))
            {
                continue;
            }

            var conversionFailed = !result.Success || string.IsNullOrWhiteSpace(result.ConvertedUrl);
            var nonAffiliated = result.Success && !result.IsAffiliated;

            if (conversionFailed && !integrity.BlockAutomaticFlowOnConversionFailure)
            {
                continue;
            }

            if (nonAffiliated && !integrity.BlockAutomaticFlowOnNonAffiliated)
            {
                continue;
            }

            if (conversionFailed || nonAffiliated)
            {
                var issue = $"{detectedStore}: {items[i].CleanedUrl}";
                failures.Add(issue);
            }
        }

        if (failures.Count == 0)
        {
            return null;
        }

        return $"Link Integrity bloqueou envio automatico. Links com falha: {string.Join(" | ", failures)}";
    }

    private async Task<string?> BuildCouponAppendixAsync(
        AutomationSettings settings,
        IReadOnlyCollection<string> convertedStores,
        CancellationToken cancellationToken)
    {
        if (convertedStores.Count == 0)
        {
            return null;
        }

        var maxPerStore = Math.Clamp(settings.CouponHub.MaxCouponsPerStore, 1, 3);
        var lines = new List<string>();

        foreach (var store in convertedStores)
        {
            var coupons = await _couponSelector.GetActiveCouponsAsync(store, maxPerStore, cancellationToken);
            foreach (var coupon in coupons)
            {
                lines.Add(FormatCouponLine(store, coupon));
            }
        }

        if (lines.Count == 0)
        {
            return null;
        }

        return $"Cupons ativos:\n{string.Join('\n', lines.Distinct(StringComparer.OrdinalIgnoreCase))}";
    }

    private async Task<string?> BuildConverterSkillAppendixAsync(
        AutomationSettings settings,
        string source,
        string originalText,
        string convertedText,
        CancellationToken cancellationToken)
    {
        var skill = settings.ConverterCouponAndPriceCompareSkill ?? new ConverterCouponAndPriceCompareSkillSettings();
        if (!skill.Enabled || !skill.AppendToWhatsApp || !source.Contains("whatsapp", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var originalMatch = UrlRegex().Match(originalText);
        var convertedMatch = UrlRegex().Match(convertedText);
        if (!originalMatch.Success)
        {
            return null;
        }

        var originalUrl = originalMatch.Value.TrimEnd('.', ',', '!', '?', ')', ']', '}');
        var convertedUrl = convertedMatch.Success
            ? convertedMatch.Value.TrimEnd('.', ',', '!', '?', ')', ']', '}')
            : null;

        var productData = await _productDataService.TryGetBestAsync(originalUrl, convertedUrl, cancellationToken);
        if (productData is null)
        {
            _logger.LogInformation(
                "Comparativo nao gerado para WhatsApp. originalUrl={OriginalUrl} convertedUrl={ConvertedUrl}",
                originalUrl,
                convertedUrl ?? "n/a");
            return null;
        }

        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(productData.CouponCode))
        {
            var couponDetails = string.IsNullOrWhiteSpace(productData.CouponDescription)
                ? string.Empty
                : $" ({productData.CouponDescription.Trim()})";
            lines.Add($"Cupom detectado: {productData.CouponCode.Trim()}{couponDetails}");
        }

        var filteredComparisons = FilterSkillComparisonResults(productData, skill);
        var primaryUrlKeys = new HashSet<string>(StringComparer.Ordinal)
        {
            NormalizeComparisonUrlKey(originalUrl),
            NormalizeComparisonUrlKey(convertedUrl)
        };

        var comparisonEntries = filteredComparisons
            .Where(x => !primaryUrlKeys.Contains(NormalizeComparisonUrlKey(x.Url)))
            // One entry per store — cheapest wins (list is already sorted by price ascending)
            .GroupBy(x => NormalizeComparisonStoreKey(x.Store), StringComparer.Ordinal)
            .Select(g => g.First())
            .OrderBy(x => x.PriceValue ?? decimal.MaxValue)
            .ToList();
        if (comparisonEntries.Count > 0)
        {
            var storeEmojis = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Shopee"] = "🛍️",
                ["Amazon"] = "📦",
                ["Mercado Livre"] = "🛒",
                ["Shein"] = "👗",
                ["Magalu"] = "🏪",
                ["Magazine Luiza"] = "🏪",
                ["Americanas"] = "🏬",
                ["Casas Bahia"] = "🏠",
            };

            var comparisonLines = new List<string>();
            foreach (var item in comparisonEntries)
            {
                var emoji = storeEmojis.TryGetValue(item.Store?.Trim() ?? string.Empty, out var e) ? e : "🔖";
                var couponPart = string.IsNullOrWhiteSpace(item.Coupon)
                    ? string.Empty
                    : $" | 🎟️ Cupom: *{item.Coupon.Trim()}*";
                comparisonLines.Add($"{emoji} *{item.Store?.Trim()}* — {item.Price}{couponPart}");
                if (!string.IsNullOrWhiteSpace(item.Url))
                    comparisonLines.Add($"🔗 {item.Url.Trim()}");
            }

            if (comparisonLines.Count > 0)
                lines.Add($"🔍 *Comparativo de preços*\n\n{string.Join('\n', comparisonLines)}");
        }

        return lines.Count == 0 ? null : string.Join('\n', lines);
    }

    private static string FormatCouponLine(string store, AffiliateCoupon coupon)
    {
        var details = string.IsNullOrWhiteSpace(coupon.Description) ? string.Empty : $" - {coupon.Description.Trim()}";
        var validity = coupon.EndsAt.HasValue ? $" (valido ate {coupon.EndsAt.Value:dd/MM HH:mm})" : string.Empty;
        var link = string.IsNullOrWhiteSpace(coupon.AffiliateLink) ? string.Empty : $"\n  Link: {coupon.AffiliateLink.Trim()}";
        return $"- [{store}] CUPOM {coupon.Code.Trim()}{details}{validity}{link}";
    }

    private static List<SkillComparisonEntry> FilterSkillComparisonResults(
        Infrastructure.ProductData.OfficialProductDataResult productData,
        ConverterCouponAndPriceCompareSkillSettings skill)
    {
        var allowedStores = new HashSet<string>(
            (skill.StoresToCompare ?? new List<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);
        var normalizedBaseTitle = NormalizeComparisonTitle(productData.Title);
        var primaryStore = NormalizeComparisonStoreKey(productData.Store);
        var primaryPriceValue = ParsePriceNumber(productData.CurrentPrice);

        var ranked = (productData.SearchResults ?? [])
            .Where(x => !string.IsNullOrWhiteSpace(x.Store))
            .Where(x => allowedStores.Count == 0 || allowedStores.Contains(x.Store))
            .Where(x => !skill.RequireExactProductMatch || IsExactEnoughComparisonMatch(normalizedBaseTitle, NormalizeComparisonTitle(x.Title)))
            .Select(x => new SkillComparisonEntry(x.Store, x.Title, x.Price, x.Url, x.Coupon, ParsePriceNumber(x.Price)))
            .Where(x => !string.Equals(NormalizeComparisonStoreKey(x.Store), primaryStore, StringComparison.Ordinal))
            .Where(x => !primaryPriceValue.HasValue || !x.PriceValue.HasValue || x.PriceValue.Value != primaryPriceValue.Value)
            .OrderBy(x => x.PriceValue ?? decimal.MaxValue)
            .ToList();

        // Remove duplicated offers when store + price + link resolve to the same candidate.
        var uniqueOffers = ranked
            .GroupBy(
                x => $"{NormalizeComparisonStoreKey(x.Store)}|{NormalizeComparisonPriceKey(x)}|{NormalizeComparisonUrlKey(x.Url)}",
                StringComparer.Ordinal)
            .Select(g => g.First())
            .GroupBy(x => NormalizeComparisonUrlKey(x.Url), StringComparer.Ordinal)
            .Select(g => g.First())
            .ToList();

        // One entry per store (cheapest wins — list is pre-sorted by price ascending).
        return uniqueOffers
            .GroupBy(x => NormalizeComparisonStoreKey(x.Store), StringComparer.Ordinal)
            .Select(g => g.First())
            .Take(Math.Clamp(skill.MaxComparisonResults, 1, 6))
            .ToList();
    }

    private static string NormalizeComparisonStoreKey(string? store)
    {
        return string.IsNullOrWhiteSpace(store)
            ? string.Empty
            : store.Trim().ToLowerInvariant();
    }

    private static string NormalizeComparisonPriceKey(SkillComparisonEntry entry)
    {
        if (entry.PriceValue.HasValue)
        {
            return entry.PriceValue.Value.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture);
        }

        return string.IsNullOrWhiteSpace(entry.Price)
            ? string.Empty
            : entry.Price.Trim().ToLowerInvariant();
    }

    private static string NormalizeComparisonUrlKey(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return string.Empty;
        }

        if (Uri.TryCreate(url.Trim(), UriKind.Absolute, out var parsed))
        {
            var builder = new UriBuilder(parsed)
            {
                Fragment = string.Empty,
                Query = string.Empty
            };

            if ((builder.Scheme == Uri.UriSchemeHttp && builder.Port == 80) ||
                (builder.Scheme == Uri.UriSchemeHttps && builder.Port == 443))
            {
                builder.Port = -1;
            }

            return builder.Uri.ToString().TrimEnd('/').ToLowerInvariant();
        }

        return url.Trim().ToLowerInvariant();
    }

    private static bool IsExactEnoughComparisonMatch(string baseTitle, string candidateTitle)
    {
        if (string.IsNullOrWhiteSpace(baseTitle) || string.IsNullOrWhiteSpace(candidateTitle))
        {
            return false;
        }

        if (candidateTitle.Contains(baseTitle, StringComparison.OrdinalIgnoreCase) ||
            baseTitle.Contains(candidateTitle, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var baseTokens = baseTitle.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var candidateTokens = candidateTitle.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (baseTokens.Count == 0)
        {
            return false;
        }

        var overlap = baseTokens.Count(token => candidateTokens.Contains(token));
        var threshold = Math.Max(2, (int)Math.Ceiling(baseTokens.Count * 0.6));
        return overlap >= threshold;
    }

    private static string NormalizeComparisonTitle(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Normalize(System.Text.NormalizationForm.FormD);
        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            var category = System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch);
            if (category == System.Globalization.UnicodeCategory.NonSpacingMark)
            {
                continue;
            }

            sb.Append(char.IsLetterOrDigit(ch) ? char.ToLowerInvariant(ch) : ' ');
        }

        return Regex.Replace(sb.ToString(), @"\s+", " ", RegexOptions.CultureInvariant).Trim();
    }

    private static decimal? ParsePriceNumber(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var clean = Regex.Replace(value, @"[^\d\.,]", "", RegexOptions.CultureInvariant).Trim();
        if (string.IsNullOrWhiteSpace(clean))
        {
            return null;
        }

        if (clean.Contains(',') && clean.Contains('.'))
        {
            clean = clean.LastIndexOf(',') > clean.LastIndexOf('.')
                ? clean.Replace(".", "").Replace(",", ".")
                : clean.Replace(",", "");
        }
        else if (clean.Contains(','))
        {
            clean = clean.Replace(",", ".");
        }

        return decimal.TryParse(clean, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private sealed record UrlWorkItem(Match Match, string CleanedUrl, string Prefix, string Suffix, bool IsBlocked, bool ShouldConvert);
    private sealed record SkillComparisonEntry(string Store, string Title, string Price, string Url, string? Coupon, decimal? PriceValue);

    private static string DetectStore(string? convertedUrl, string originalUrl)
    {
        var url = convertedUrl ?? originalUrl;
        var lower = url.ToLowerInvariant();
        if (lower.Contains("images-na.ssl-images-amazon.com", StringComparison.OrdinalIgnoreCase))
        {
            return "Unknown";
        }

        if (lower.Contains("amazon.") || lower.Contains("amzn.to") || lower.Contains("a.co") || lower.Contains("amzlink.to") || lower.Contains("amzn.divulgador.link")) return "Amazon";
        if (lower.Contains("mercadolivre") || lower.Contains("mercadolibre")) return "Mercado Livre";
        if (lower.Contains("meli.co") || lower.Contains("meli.la")) return "Mercado Livre";
        if (lower.Contains("shopee") || lower.Contains("shope.ee") || lower.Contains("s.shopee")) return "Shopee";
        if (lower.Contains("shein")) return "Shein";
        return "Unknown";
    }

    private static bool ShouldAttemptAffiliateConversion(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        var path = uri.AbsolutePath;

        if (host.Contains("reidasofertas.ia.br", StringComparison.Ordinal))
        {
            if (path.StartsWith("/bio", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/catalogo", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/dashboard", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/api", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (path.StartsWith("/r/", StringComparison.OrdinalIgnoreCase))
            {
                // Already tracked by our redirector.
                return false;
            }
        }

        if (host.Contains("amazon.", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("amzn.to", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("a.co", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("amzlink.to", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("amzn.divulgador.link", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("meli.co", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("meli.la", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("shopee", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("shp.ee", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("shein", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Some campaigns arrive through generic shorteners and should still be evaluated.
        if (host.Equals("tinyurl.com", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("bit.ly", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("cutt.ly", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("compre.link", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static string NormalizeUrl(string url)
    {
        if (!Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var uri))
        {
            return url?.Trim() ?? string.Empty;
        }

        var builder = new UriBuilder(uri)
        {
            Fragment = string.Empty
        };
        if ((builder.Scheme == Uri.UriSchemeHttp && builder.Port == 80) ||
            (builder.Scheme == Uri.UriSchemeHttps && builder.Port == 443))
        {
            builder.Port = -1;
        }

        return builder.Uri.ToString().TrimEnd('/');
    }
    public async Task<(string EnrichedText, string? ProductImageUrl, string? ProductVideoUrl)> EnrichTextWithProductDataAsync(
        string convertedText,
        string originalText,
        CancellationToken cancellationToken)
    {
        try
        {
            var lowerConverted = convertedText.ToLowerInvariant();
            var lowerOriginal = originalText.ToLowerInvariant();
            var isAmazon = lowerConverted.Contains("amazon.")
                || lowerConverted.Contains("amzn.to")
                || lowerConverted.Contains("a.co/")
                || lowerConverted.Contains("amzlink.to")
                || lowerConverted.Contains("amzn.divulgador.link")
                || lowerOriginal.Contains("amazon.")
                || lowerOriginal.Contains("amzn.to")
                || lowerOriginal.Contains("a.co/")
                || lowerOriginal.Contains("amzlink.to")
                || lowerOriginal.Contains("amzn.divulgador.link");
            var isShopee = lowerConverted.Contains("shopee")
                || lowerConverted.Contains("shp.ee")
                || lowerConverted.Contains("s.shopee")
                || lowerOriginal.Contains("shopee")
                || lowerOriginal.Contains("shp.ee")
                || lowerOriginal.Contains("s.shopee");
            var isML = lowerConverted.Contains("mercadolivre")
                || lowerConverted.Contains("mercadolibre")
                || lowerConverted.Contains("meli.")
                || lowerOriginal.Contains("mercadolivre")
                || lowerOriginal.Contains("mercadolibre")
                || lowerOriginal.Contains("meli.");

            if (!isAmazon && !isShopee && !isML)
            {
                return (convertedText, null, null);
            }

            var urlMatch = Regex.Match(originalText, @"https?://[^\s]+", RegexOptions.IgnoreCase);
            if (!urlMatch.Success)
            {
                return (convertedText, null, null);
            }

            var originalUrl = urlMatch.Value.TrimEnd('.', ',', '!', '?', ')', ']', '}');
            var convertedUrlMatch = Regex.Match(convertedText, @"https?://[^\s]+", RegexOptions.IgnoreCase);
            var convertedUrl = convertedUrlMatch.Success ? convertedUrlMatch.Value.TrimEnd('.', ',', '!', '?', ')', ']', '}') : null;

            var productData = await _productDataService.TryGetBestAsync(originalUrl, convertedUrl, cancellationToken);
            if (productData is null && isML)
            {
                // Fallback: force conversion of ML short/social URL and retry product data.
                var candidate = convertedUrl ?? originalUrl;
                if (!string.IsNullOrWhiteSpace(candidate))
                {
                    var convertedCandidate = await _affiliateLinkService.ConvertAsync(candidate, cancellationToken, source: "manual");
                    if (convertedCandidate.Success && !string.IsNullOrWhiteSpace(convertedCandidate.ConvertedUrl))
                    {
                        productData = await _productDataService.TryGetBestAsync(candidate, convertedCandidate.ConvertedUrl, cancellationToken);
                    }
                }
            }
            if (productData is null)
            {
                return (convertedText, null, null);
            }

            var enrichParts = new List<string>();
            if (!string.IsNullOrWhiteSpace(productData.CurrentPrice))
            {
                var pricePart = $"💰 {productData.CurrentPrice.Trim()}";
                if (productData.DiscountPercent.HasValue && productData.DiscountPercent.Value > 0)
                {
                    pricePart += $" ({productData.DiscountPercent.Value}% OFF)";
                }
                enrichParts.Add(pricePart);
            }
            else if (productData.DiscountPercent.HasValue && productData.DiscountPercent.Value > 0)
            {
                enrichParts.Add($"🏷️ {productData.DiscountPercent.Value}% OFF");
            }

            var enrichedText = convertedText;
            if (enrichParts.Count > 0)
            {
                var enrichBlock = string.Join("\n", enrichParts);
                enrichedText = $"{enrichBlock}\n\n{convertedText}";
            }

            var bestImage = productData.Images.FirstOrDefault();

            _logger.LogInformation(
                "Produto enriquecido via {DataSource}. Store={Store} Price={Price} Discount={Discount} HasImage={HasImage}",
                productData.DataSource,
                productData.Store,
                productData.CurrentPrice ?? "n/a",
                productData.DiscountPercent?.ToString() ?? "n/a",
                !string.IsNullOrWhiteSpace(bestImage));

            return (enrichedText, bestImage, productData.VideoUrl);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Falha ao enriquecer texto com metadados de produto. Retornando texto original.");
            return (convertedText, null, null);
        }
    }
}
