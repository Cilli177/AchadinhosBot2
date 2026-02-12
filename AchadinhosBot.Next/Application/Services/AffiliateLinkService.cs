using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed class AffiliateLinkService : IAffiliateLinkService
{
    private readonly AffiliateOptions _options;
    private readonly ILogger<AffiliateLinkService> _logger;

    public AffiliateLinkService(IOptions<AffiliateOptions> options, ILogger<AffiliateLinkService> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public Task<string?> ConvertAsync(string rawUrl, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return Task.FromResult<string?>(null);
        }

        var host = uri.Host.ToLowerInvariant();

        if (IsAmazonHost(host))
        {
            var amazon = ApplyOrReplaceQuery(uri, "tag", _options.AmazonTag);
            return Task.FromResult<string?>(amazon);
        }

        if (host.Contains("shein.com"))
        {
            var shein = ApplyOrReplaceQuery(uri, "url_from", _options.SheinId);
            return Task.FromResult<string?>(shein);
        }

        _logger.LogDebug("Host não suportado para afiliação: {Host}", host);
        return Task.FromResult<string?>(null);
    }

    private static bool IsAmazonHost(string host)
        => host == "amazon.com" || host == "amazon.com.br" || host == "amzn.to" || host.EndsWith(".amazon.com") || host.EndsWith(".amazon.com.br");

    private static string ApplyOrReplaceQuery(Uri uri, string key, string value)
    {
        var pairs = ParseQuery(uri.Query);
        pairs[key] = value;

        var encodedQuery = string.Join("&", pairs.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var ub = new UriBuilder(uri)
        {
            Query = encodedQuery
        };

        return ub.Uri.ToString();
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return result;
        }

        var clean = query.TrimStart('?');
        foreach (var part in clean.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
            {
                result[Uri.UnescapeDataString(part)] = string.Empty;
                continue;
            }

            var k = Uri.UnescapeDataString(part[..idx]);
            var v = Uri.UnescapeDataString(part[(idx + 1)..]);
            result[k] = v;
        }

        return result;
    }
}
