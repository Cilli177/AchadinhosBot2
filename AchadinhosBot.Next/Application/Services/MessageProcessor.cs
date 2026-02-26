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
    private readonly IConversionLogStore _conversionLogStore;
    private readonly ICouponSelector _couponSelector;
    private readonly ISettingsStore _settingsStore;
    private readonly IMercadoLivreApprovalStore _mercadoLivreApprovalStore;
    private readonly ILogger<MessageProcessor> _logger;

    public MessageProcessor(
        IAffiliateLinkService affiliateLinkService,
        IConversionLogStore conversionLogStore,
        ICouponSelector couponSelector,
        ISettingsStore settingsStore,
        IMercadoLivreApprovalStore mercadoLivreApprovalStore,
        ILogger<MessageProcessor> logger)
    {
        _affiliateLinkService = affiliateLinkService;
        _conversionLogStore = conversionLogStore;
        _couponSelector = couponSelector;
        _settingsStore = settingsStore;
        _mercadoLivreApprovalStore = mercadoLivreApprovalStore;
        _logger = logger;
    }

    public async Task<ConversionResult> ProcessAsync(
        string input,
        string source,
        CancellationToken cancellationToken,
        long? originChatId = null,
        long? destinationChatId = null,
        string? originChatRef = null,
        string? destinationChatRef = null)
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
            items.Add(new UrlWorkItem(match, cleanedUrl, prefix, suffix, isBlocked));
        }

        var mercadoLivreUrls = items
            .Where(x => IsMercadoLivreUrl(x.CleanedUrl))
            .Select(x => x.CleanedUrl)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var isAutomaticSource = IsAutomaticSource(source);
        MercadoLivreComplianceSettings? mercadoLivreCompliance = null;

        if (mercadoLivreUrls.Length > 0)
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
                        ExtractedUrls = mercadoLivreUrls.ToList(),
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
                    OriginalUrl = string.Join(" | ", mercadoLivreUrls),
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
                    string.Join(" | ", mercadoLivreUrls));

                return new ConversionResult(false, null, 0, source);
            }
        }

        var tasks = new Task<AffiliateLinkResult>[items.Count];
        for (var i = 0; i < items.Count; i++)
        {
            tasks[i] = items[i].IsBlocked
                ? Task.FromResult(new AffiliateLinkResult(false, null, "Unknown", false, null, "Link bloqueado", false, null))
                : _affiliateLinkService.ConvertAsync(items[i].CleanedUrl, cancellationToken);
        }

        await Task.WhenAll(tasks);

        if (mercadoLivreUrls.Length > 0 && isAutomaticSource)
        {
            var invalidMercadoLivreUrls = new List<string>();
            for (var i = 0; i < items.Count; i++)
            {
                var item = items[i];
                if (!IsMercadoLivreUrl(item.CleanedUrl))
                {
                    continue;
                }

                var result = tasks[i].Result;
                var valid = result.Success && result.IsAffiliated && !string.IsNullOrWhiteSpace(result.ConvertedUrl);
                if (!valid)
                {
                    invalidMercadoLivreUrls.Add(item.CleanedUrl);
                }
            }

            if (invalidMercadoLivreUrls.Count > 0)
            {
                var reason = "Verificacao obrigatoria do Mercado Livre falhou. Link nao sera enviado automaticamente.";
                if (mercadoLivreCompliance?.RequireManualApproval ?? true)
                {
                    await _mercadoLivreApprovalStore.AppendAsync(new MercadoLivrePendingApproval
                    {
                        Source = source,
                        Reason = reason,
                        OriginalText = input,
                        ExtractedUrls = invalidMercadoLivreUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
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
                    OriginalUrl = string.Join(" | ", invalidMercadoLivreUrls.Distinct(StringComparer.OrdinalIgnoreCase)),
                    ConvertedUrl = string.Empty,
                    OriginChatId = originChatId,
                    DestinationChatId = destinationChatId,
                    OriginChatRef = originChatRef,
                    DestinationChatRef = destinationChatRef,
                    ElapsedMs = sw.ElapsedMilliseconds
                }, cancellationToken);

                _logger.LogWarning("Bloqueio automatico Mercado Livre por validacao obrigatoria. Source={Source} Urls={Urls}",
                    source,
                    string.Join(" | ", invalidMercadoLivreUrls.Distinct(StringComparer.OrdinalIgnoreCase)));

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
               || host.Contains("meli.co", StringComparison.OrdinalIgnoreCase);
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

    private static string FormatCouponLine(string store, AffiliateCoupon coupon)
    {
        var details = string.IsNullOrWhiteSpace(coupon.Description) ? string.Empty : $" - {coupon.Description.Trim()}";
        var validity = coupon.EndsAt.HasValue ? $" (valido ate {coupon.EndsAt.Value:dd/MM HH:mm})" : string.Empty;
        var link = string.IsNullOrWhiteSpace(coupon.AffiliateLink) ? string.Empty : $"\n  Link: {coupon.AffiliateLink.Trim()}";
        return $"- [{store}] CUPOM {coupon.Code.Trim()}{details}{validity}{link}";
    }

    private sealed record UrlWorkItem(Match Match, string CleanedUrl, string Prefix, string Suffix, bool IsBlocked);

    private static string DetectStore(string? convertedUrl, string originalUrl)
    {
        var url = convertedUrl ?? originalUrl;
        var lower = url.ToLowerInvariant();
        if (lower.Contains("amazon.") || lower.Contains("amzn.to") || lower.Contains("a.co")) return "Amazon";
        if (lower.Contains("mercadolivre") || lower.Contains("mercadolibre")) return "Mercado Livre";
        if (lower.Contains("shopee") || lower.Contains("shope.ee") || lower.Contains("s.shopee")) return "Shopee";
        if (lower.Contains("shein")) return "Shein";
        return "Unknown";
    }
}
