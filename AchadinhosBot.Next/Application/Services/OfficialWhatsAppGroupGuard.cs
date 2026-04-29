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

        if (!urls.Any(IsTrackedOfferUrl))
        {
            return new OfficialWhatsAppGroupGuardResult(false, "no_tracked_offer_link", "Grupo oficial exige link rastreado do dominio oficial.");
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
        => url.Contains("reidasofertas.ia.br/r/", StringComparison.OrdinalIgnoreCase)
           || url.Contains("tinyurl.com/", StringComparison.OrdinalIgnoreCase)
           || url.Contains("shope.ee/", StringComparison.OrdinalIgnoreCase);

    private static bool IsAllowedNonOfferUrl(string url)
        => url.Contains("reidasofertas.ia.br/bio", StringComparison.OrdinalIgnoreCase)
           || url.Contains("bio.reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase)
           || url.Contains("chat.whatsapp.com/FhkbgV9fnUjKnOM4KGDCPX", StringComparison.OrdinalIgnoreCase);

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
               || url.Contains("compre.link", StringComparison.OrdinalIgnoreCase)
               || url.Contains("bit.ly", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();
}
