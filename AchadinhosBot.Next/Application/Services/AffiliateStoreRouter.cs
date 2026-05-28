namespace AchadinhosBot.Next.Application.Services;

public static class AffiliateStoreRouter
{
    public const string Amazon = "Amazon";
    public const string MercadoLivre = "Mercado Livre";
    public const string Shopee = "Shopee";
    public const string Shein = "Shein";
    public const string Unknown = "Unknown";

    public static string ResolveStore(Uri uri)
    {
        var host = NormalizeHost(uri.Host);
        var absolute = uri.AbsoluteUri;

        if (IsAmazon(uri, host))
        {
            return Amazon;
        }

        if (IsShein(uri, host))
        {
            return Shein;
        }

        if (IsMercadoLivre(uri, host))
        {
            return MercadoLivre;
        }

        if (IsShopee(uri, host))
        {
            return Shopee;
        }

        return Unknown;
    }

    public static bool IsAmazon(Uri uri, string? normalizedHost = null)
    {
        var host = NormalizeHost(normalizedHost ?? uri.Host);
        return host == "amazon.com"
               || host == "amazon.com.br"
               || host == "amzn.to"
               || host == "a.co"
               || host == "amzlink.to"
               || host == "amzn.divulgador.link"
               || host.EndsWith(".amazon.com", StringComparison.OrdinalIgnoreCase)
               || host.EndsWith(".amazon.com.br", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsAmazonShort(Uri uri, string? normalizedHost = null)
    {
        var host = NormalizeHost(normalizedHost ?? uri.Host);
        return host == "amzn.to"
               || host == "a.co"
               || host == "amzlink.to"
               || host == "amzn.divulgador.link";
    }

    public static bool IsMercadoLivre(Uri uri, string? normalizedHost = null)
    {
        var host = NormalizeHost(normalizedHost ?? uri.Host);
        return host.Contains("mercadolivre.com", StringComparison.OrdinalIgnoreCase)
               || host.Contains("mercadolivre.com.br", StringComparison.OrdinalIgnoreCase)
               || host.Contains("mercadolibre.com", StringComparison.OrdinalIgnoreCase)
               || host.Equals("meli.la", StringComparison.OrdinalIgnoreCase)
               || host.Equals("meli.co", StringComparison.OrdinalIgnoreCase)
               || uri.AbsoluteUri.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
               || uri.AbsoluteUri.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsShopee(Uri uri, string? normalizedHost = null)
    {
        var host = NormalizeHost(normalizedHost ?? uri.Host);
        return host.Contains("shopee", StringComparison.OrdinalIgnoreCase)
               || host.Contains("shopee.com", StringComparison.OrdinalIgnoreCase)
               || host.Contains("shopee.com.br", StringComparison.OrdinalIgnoreCase)
               || host.Contains("shopeemobile.com", StringComparison.OrdinalIgnoreCase)
               || uri.AbsoluteUri.Contains("shopee", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsShein(Uri uri, string? normalizedHost = null)
    {
        var host = NormalizeHost(normalizedHost ?? uri.Host);
        return host.Contains("shein.com", StringComparison.OrdinalIgnoreCase);
    }

    public static string NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return string.Empty;
        }

        return new string(host
            .Trim()
            .Trim('.')
            .ToLowerInvariant()
            .Where(ch => char.IsLetterOrDigit(ch) || ch is '.' or '-')
            .ToArray());
    }
}
