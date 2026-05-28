using System.Text.RegularExpressions;

namespace AchadinhosBot.Next.Application.Services;

public static partial class TrackingIdDecorator
{
    public static string Decorate(string trackingId, string? campaign = null, string? source = null)
    {
        var marker = ResolveMarker(campaign, source);
        if (marker is null || IsDecorated(trackingId))
        {
            return trackingId;
        }

        var separator = trackingId.IndexOf('-', StringComparison.Ordinal);
        if (separator <= 0 || separator >= trackingId.Length - 1)
        {
            return trackingId;
        }

        return $"{trackingId[..(separator + 1)]}{marker}{trackingId[(separator + 1)..]}";
    }

    public static DecoratedTrackingId Resolve(string id)
    {
        var trimmed = (id ?? string.Empty).Trim();
        var match = DecoratedTrackingIdRegex().Match(trimmed);
        if (!match.Success)
        {
            return new DecoratedTrackingId(trimmed, false, null, null);
        }

        var marker = match.Groups["marker"].Value.ToUpperInvariant();
        var campaign = MarkerToCampaign(marker);
        if (campaign is null)
        {
            return new DecoratedTrackingId(trimmed, false, null, null);
        }

        var lookupId = $"{match.Groups["prefix"].Value.ToUpperInvariant()}-{match.Groups["number"].Value}";
        var source = marker switch
        {
            "K" => "c",
            "D" => "bio",
            _ => "wg"
        };

        return new DecoratedTrackingId(lookupId, true, source, campaign);
    }

    public static bool IsAllowedOfferTrackingId(string? id)
    {
        var resolved = Resolve(id ?? string.Empty);
        var lookup = resolved.LookupId;
        return lookup.StartsWith("AM-", StringComparison.OrdinalIgnoreCase)
               || lookup.StartsWith("SP-", StringComparison.OrdinalIgnoreCase)
               || lookup.StartsWith("ML-", StringComparison.OrdinalIgnoreCase)
               || lookup.StartsWith("SHE-", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsBlockedOfferTrackingId(string? id)
    {
        var resolved = Resolve(id ?? string.Empty);
        var lookup = resolved.LookupId;
        return lookup.StartsWith("MGL-", StringComparison.OrdinalIgnoreCase)
               || lookup.StartsWith("LK-", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDecorated(string trackingId)
        => DecoratedTrackingIdRegex().IsMatch((trackingId ?? string.Empty).Trim());

    private static string? ResolveMarker(string? campaign, string? source)
    {
        var value = $"{campaign} {source}";
        return value.Contains("casa", StringComparison.OrdinalIgnoreCase) ? "C"
            : value.Contains("beleza", StringComparison.OrdinalIgnoreCase) ? "B"
            : value.Contains("fitness_health", StringComparison.OrdinalIgnoreCase) || value.Contains("fitness", StringComparison.OrdinalIgnoreCase) ? "F"
            : value.Contains("moda", StringComparison.OrdinalIgnoreCase) ? "M"
            : value.Contains("tech", StringComparison.OrdinalIgnoreCase) ? "T"
            : value.Contains("ate_50", StringComparison.OrdinalIgnoreCase) ? "A"
            : value.Contains("mercado_livre", StringComparison.OrdinalIgnoreCase) ? "L"
            : value.Contains("geral", StringComparison.OrdinalIgnoreCase) ? "G"
            : value.Contains("catalog", StringComparison.OrdinalIgnoreCase) ? "K"
            : value.Contains("bio", StringComparison.OrdinalIgnoreCase) || value.Contains("destaque", StringComparison.OrdinalIgnoreCase) ? "D"
            : value.Contains("whatsapp", StringComparison.OrdinalIgnoreCase) || value.Equals("wg", StringComparison.OrdinalIgnoreCase) ? "W"
            : null;
    }

    private static string? MarkerToCampaign(string marker)
        => marker switch
        {
            "C" => "niche_live_casa",
            "B" => "niche_live_beleza",
            "F" => "niche_live_fitness_health",
            "M" => "niche_live_moda",
            "T" => "niche_live_tech",
            "A" => "niche_live_ate_50",
            "L" => "niche_live_mercado_livre",
            "G" => "niche_live_geral",
            "K" => "catalogo_prod",
            "D" => "bio",
            "W" => "whatsapp",
            _ => null
        };

    [GeneratedRegex(@"^(?<prefix>[A-Za-z]{2,3})-(?<marker>[A-Za-z])(?<number>\d+)$", RegexOptions.CultureInvariant)]
    private static partial Regex DecoratedTrackingIdRegex();
}

public sealed record DecoratedTrackingId(string LookupId, bool Decorated, string? Source, string? Campaign);
