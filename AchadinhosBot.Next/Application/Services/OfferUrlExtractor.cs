using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Compliance;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class OfferUrlExtractor : IOfferUrlExtractor
{
    private static readonly string[] BlockedHosts =
    {
        "tidd.ly",
        "natura.com",
        "magazineluiza.com.br",
        "magazineluiza.com",
        "magalu.com"
    };

    public IReadOnlyList<OfferUrlCandidate> Extract(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return Array.Empty<OfferUrlCandidate>();
        }

        var matches = UrlRegex().Matches(input);
        if (matches.Count == 0)
        {
            return Array.Empty<OfferUrlCandidate>();
        }

        var candidates = new List<OfferUrlCandidate>(matches.Count);
        foreach (Match match in matches)
        {
            var cleanedUrl = CleanUrl(match.Value, out var prefix, out var suffix);
            var isBlocked = IsBlockedUrl(cleanedUrl);
            candidates.Add(new OfferUrlCandidate(
                match.Value,
                cleanedUrl,
                prefix,
                suffix,
                match.Index,
                match.Length,
                isBlocked,
                !isBlocked && ShouldAttemptAffiliateConversion(cleanedUrl)));
        }

        return candidates;
    }

    public static string CleanUrl(string raw, out string prefix, out string suffix)
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

        return start > end ? raw : raw[start..(end + 1)];
    }

    public static bool IsBlockedUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return true;
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            return true;
        }

        if (IsUnsafeHost(uri.Host))
        {
            return true;
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

    public static bool ShouldAttemptAffiliateConversion(string url)
    {
        if (InstitutionalUrlGuard.ShouldPreserve(url))
        {
            return false;
        }

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

        return host.Equals("tinyurl.com", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("bit.ly", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("cutt.ly", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("compre.link", StringComparison.OrdinalIgnoreCase);
    }

    public static string TryGetSafeHost(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : "invalid";

    private static bool IsTrimChar(char c)
        => c is '"' or '\'' or '`' or '.' or ',' or ';' or ':' or ')' or ']' or '}' or '!' or '?';

    private static bool IsUnsafeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return true;
        }

        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (normalized is "localhost" or "127.0.0.1" or "::1" ||
            normalized.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!System.Net.IPAddress.TryParse(normalized, out var address))
        {
            return false;
        }

        if (System.Net.IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return bytes[0] == 10
                   || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                   || (bytes[0] == 192 && bytes[1] == 168)
                   || (bytes[0] == 169 && bytes[1] == 254);
        }

        return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal;
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();
}
