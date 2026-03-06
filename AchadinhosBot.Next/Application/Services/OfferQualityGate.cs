using System.Text.RegularExpressions;

namespace AchadinhosBot.Next.Application.Services;

public sealed record OfferQualityGateResult(bool Allowed, string Reason, string? Detail = null);

public static class OfferQualityGate
{
    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static OfferQualityGateResult ValidateForAutoForward(string? text, bool hasImageCandidate)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return new OfferQualityGateResult(false, "empty_text", "Oferta sem texto.");
        }

        var urls = UrlRegex.Matches(text)
            .Select(m => m.Value.Trim())
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (urls.Length == 0)
        {
            return new OfferQualityGateResult(false, "no_urls", "Oferta sem link.");
        }

        foreach (var url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host))
            {
                return new OfferQualityGateResult(false, "invalid_url_format", $"URL invalida: {url}");
            }
        }

        var plainText = UrlRegex.Replace(text, " ").Trim();
        if (plainText.Length < 12)
        {
            return new OfferQualityGateResult(false, "insufficient_context", "Oferta sem contexto minimo (titulo/descricao).");
        }

        var hasMercadoLivre = urls.Any(IsMercadoLivreUrlLike);
        if (hasMercadoLivre && !hasImageCandidate)
        {
            return new OfferQualityGateResult(false, "mercadolivre_without_image", "Oferta Mercado Livre sem imagem.");
        }

        return new OfferQualityGateResult(true, "ok");
    }

    private static bool IsMercadoLivreUrlLike(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return false;
        }

        return url.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
            || url.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
            || url.Contains("meli.la", StringComparison.OrdinalIgnoreCase)
            || url.Contains("compre.link", StringComparison.OrdinalIgnoreCase);
    }
}
