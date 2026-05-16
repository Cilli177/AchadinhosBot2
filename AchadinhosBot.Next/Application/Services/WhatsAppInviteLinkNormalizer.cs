using System.Text.RegularExpressions;

namespace AchadinhosBot.Next.Application.Services;

public static partial class WhatsAppInviteLinkNormalizer
{
    public const string OfficialInviteUrl = "https://chat.whatsapp.com/GosnHVUa2lE0nYGhO6an4x";
    public const string OfficialBioUrl = "https://bio.reidasofertas.ia.br";

    public static string NormalizeOfficialInviteBlock(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text ?? string.Empty;
        }

        var normalized = text;
        normalized = LinkDosGruposRegex().Replace(normalized, $"LINK DOS GRUPOS: {OfficialInviteUrl}");
        normalized = LinkDosGruposSpacedRegex().Replace(normalized, $"LINK DOS GRUPOS:\n{OfficialInviteUrl}");
        normalized = NormalizeOfficialFooterLinks(normalized);
        return normalized;
    }

    public static string NormalizeOfficialFooterLinks(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text ?? string.Empty;
        }

        var normalized = text;
        normalized = BioAbsoluteRegex().Replace(normalized, OfficialBioUrl);
        normalized = BioSubdomainRegex().Replace(normalized, OfficialBioUrl);
        normalized = BioBareRegex().Replace(normalized, OfficialBioUrl);
        return normalized;
    }

    public static bool IsWhatsAppInviteUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return string.Equals(uri.Host, "chat.whatsapp.com", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsApprovedInviteUrl(string? url, IEnumerable<string?> additionalApprovedUrls)
    {
        if (!TryNormalizeInviteUrl(url, out var normalizedUrl))
        {
            return false;
        }

        if (TryNormalizeInviteUrl(OfficialInviteUrl, out var normalizedOfficial)
            && string.Equals(normalizedUrl, normalizedOfficial, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return additionalApprovedUrls
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Any(candidate => TryNormalizeInviteUrl(candidate, out var normalizedCandidate)
                              && string.Equals(normalizedUrl, normalizedCandidate, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TryNormalizeInviteUrl(string? url, out string normalized)
    {
        normalized = string.Empty;
        if (!IsWhatsAppInviteUrl(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        normalized = $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath.TrimEnd('/')}";
        return true;
    }

    [GeneratedRegex(@"LINK DOS GRUPOS:\s*https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LinkDosGruposRegex();

    [GeneratedRegex(@"LINK DOS GRUPOS:\s*(?:\r?\n)+\s*https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LinkDosGruposSpacedRegex();

    [GeneratedRegex(@"https?://reidasofertas\.ia\.br/bio", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BioAbsoluteRegex();

    [GeneratedRegex(@"https?://bio\.reidasofertas\.ia\.br(?:/bio)?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BioSubdomainRegex();

    [GeneratedRegex(@"(?<!https?://)bio\.reidasofertas\.ia\.br(?:/bio)?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BioBareRegex();
}
