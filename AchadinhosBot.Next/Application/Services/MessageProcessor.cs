using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class MessageProcessor : IMessageProcessor
{
    private readonly IAffiliateLinkService _affiliateLinkService;
    private readonly ILogger<MessageProcessor> _logger;

    public MessageProcessor(IAffiliateLinkService affiliateLinkService, ILogger<MessageProcessor> logger)
    {
        _affiliateLinkService = affiliateLinkService;
        _logger = logger;
    }

    public async Task<ConversionResult> ProcessAsync(string input, string source, CancellationToken cancellationToken)
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

        var sb = new StringBuilder(input.Length + 128);
        var lastIndex = 0;
        var converted = 0;

        foreach (Match match in matches)
        {
            sb.Append(input, lastIndex, match.Index - lastIndex);

            var cleanedUrl = CleanUrl(match.Value, out var prefix, out var suffix);
            var convertedUrl = await _affiliateLinkService.ConvertAsync(cleanedUrl, cancellationToken);

            if (!string.IsNullOrWhiteSpace(convertedUrl))
            {
                sb.Append(prefix);
                sb.Append(convertedUrl);
                sb.Append(suffix);
                converted++;
            }
            else
            {
                sb.Append(match.Value);
            }

            lastIndex = match.Index + match.Length;
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
}
