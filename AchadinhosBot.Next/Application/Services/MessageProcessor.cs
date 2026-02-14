using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class MessageProcessor : IMessageProcessor
{
    private readonly IAffiliateLinkService _affiliateLinkService;
    private readonly IConversionLogStore _conversionLogStore;
    private readonly ILogger<MessageProcessor> _logger;

    public MessageProcessor(IAffiliateLinkService affiliateLinkService, IConversionLogStore conversionLogStore, ILogger<MessageProcessor> logger)
    {
        _affiliateLinkService = affiliateLinkService;
        _conversionLogStore = conversionLogStore;
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

        var items = new List<UrlWorkItem>(matches.Count);
        foreach (Match match in matches)
        {
            var cleanedUrl = CleanUrl(match.Value, out var prefix, out var suffix);
            var isBlocked = IsBlockedUrl(cleanedUrl);
            items.Add(new UrlWorkItem(match, cleanedUrl, prefix, suffix, isBlocked));
        }

        var tasks = new Task<AffiliateLinkResult>[items.Count];
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < items.Count; i++)
        {
            tasks[i] = items[i].IsBlocked
                ? Task.FromResult(new AffiliateLinkResult(false, null, "Unknown", false, null, "Link bloqueado", false, null))
                : _affiliateLinkService.ConvertAsync(items[i].CleanedUrl, cancellationToken);
        }

        await Task.WhenAll(tasks);

        var sb = new StringBuilder(input.Length + 128);
        var lastIndex = 0;
        var converted = 0;

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
