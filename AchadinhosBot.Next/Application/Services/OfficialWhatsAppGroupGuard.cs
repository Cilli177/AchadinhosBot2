using System.Text.RegularExpressions;

namespace AchadinhosBot.Next.Application.Services;

public sealed record OfficialWhatsAppGroupGuardResult(bool Allowed, string Reason, string? Detail = null);

public static partial class OfficialWhatsAppGroupGuard
{
    public static OfficialWhatsAppGroupGuardResult Validate(bool isOfficialDestination, string? text, bool hasImageCandidate, bool hasActualImage)
    {
        if (!isOfficialDestination)
        {
            return new OfficialWhatsAppGroupGuardResult(true, "not_official_destination");
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            return new OfficialWhatsAppGroupGuardResult(false, "empty_text", "Texto vazio para grupo oficial.");
        }

        var urls = UrlRegex().Matches(text)
            .Select(m => m.Value.Trim())
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (urls.Length == 0)
        {
            return new OfficialWhatsAppGroupGuardResult(false, "no_urls", "Oferta sem links.");
        }

        var insecureTrackingUrl = urls.FirstOrDefault(IsInsecureTrackedOfferUrl);
        if (!string.IsNullOrWhiteSpace(insecureTrackingUrl))
        {
            return new OfficialWhatsAppGroupGuardResult(false, "insecure_tracking_link", $"Link rastreado nao permitido no grupo oficial: {insecureTrackingUrl}");
        }

        var trackedWithVisibleAttribution = urls.FirstOrDefault(HasVisibleTrackingAttribution);
        if (!string.IsNullOrWhiteSpace(trackedWithVisibleAttribution))
        {
            return new OfficialWhatsAppGroupGuardResult(false, "visible_tracking_query", $"Link rastreado deve usar ID decorado, sem src/camp visivel: {trackedWithVisibleAttribution}");
        }

        if (!urls.Any(IsAllowedTrackedOfferUrl))
        {
            return new OfficialWhatsAppGroupGuardResult(false, "no_tracked_offer_link", "Grupo oficial exige link rastreado aprovado do dominio oficial.");
        }

        var rawMarketplaceUrl = urls.FirstOrDefault(IsRawMarketplaceUrl);
        if (!string.IsNullOrWhiteSpace(rawMarketplaceUrl))
        {
            return new OfficialWhatsAppGroupGuardResult(false, "raw_marketplace_url", $"URL nao convertida detectada: {rawMarketplaceUrl}");
        }

        if (!hasActualImage)
        {
            var detail = hasImageCandidate
                ? "Imagem candidata nao virou midia valida no envio final."
                : "Grupo oficial exige imagem valida.";
            return new OfficialWhatsAppGroupGuardResult(false, "image_required", detail);
        }

        return new OfficialWhatsAppGroupGuardResult(true, "ok");
    }

    private static bool IsTrackedOfferUrl(string url)
        => url.Contains("reidasofertas.ia.br/r/", StringComparison.OrdinalIgnoreCase);

    private static bool IsAllowedTrackedOfferUrl(string url)
        => TryExtractTrackingId(url, out var id) && TrackingIdDecorator.IsAllowedOfferTrackingId(id);

    private static bool IsInsecureTrackedOfferUrl(string url)
    {
        if (!TryExtractTrackingId(url, out var id))
        {
            return false;
        }

        return TrackingIdDecorator.IsBlockedOfferTrackingId(id)
               || !TrackingIdDecorator.IsAllowedOfferTrackingId(id);
    }

    private static bool HasVisibleTrackingAttribution(string url)
    {
        if (!IsTrackedOfferUrl(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var query = uri.Query;
        return query.Contains("src=", StringComparison.OrdinalIgnoreCase)
               || query.Contains("camp=", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryExtractTrackingId(string url, out string id)
    {
        id = string.Empty;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase) &&
            !uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var match = Regex.Match(uri.AbsolutePath, @"^/r/([^/?#]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success)
        {
            return false;
        }

        id = Uri.UnescapeDataString(match.Groups[1].Value);
        return true;
    }

    private static bool IsAllowedNonOfferUrl(string url)
        => url.Contains("reidasofertas.ia.br/bio", StringComparison.OrdinalIgnoreCase)
           || url.Contains("bio.reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase)
           || url.Contains(WhatsAppInviteLinkNormalizer.OfficialInviteUrl, StringComparison.OrdinalIgnoreCase);

    private static bool IsRawMarketplaceUrl(string url)
    {
        if (IsTrackedOfferUrl(url) || IsAllowedNonOfferUrl(url))
        {
            return false;
        }

        return url.Contains("amazon.", StringComparison.OrdinalIgnoreCase)
               || url.Contains("amzn.to", StringComparison.OrdinalIgnoreCase)
               || url.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
               || url.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
               || url.Contains("meli.la", StringComparison.OrdinalIgnoreCase)
               || url.Contains("meli.co", StringComparison.OrdinalIgnoreCase)
               || (url.Contains("shopee.", StringComparison.OrdinalIgnoreCase) && !url.Contains("shope.ee", StringComparison.OrdinalIgnoreCase))
               || url.Contains("magalu", StringComparison.OrdinalIgnoreCase)
               || url.Contains("magazineluiza", StringComparison.OrdinalIgnoreCase)
               || url.Contains("magazinevoce", StringComparison.OrdinalIgnoreCase)
               || url.Contains("compre.link", StringComparison.OrdinalIgnoreCase)
               || url.Contains("bit.ly", StringComparison.OrdinalIgnoreCase)
               || url.Contains("tidd.ly", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();
}
