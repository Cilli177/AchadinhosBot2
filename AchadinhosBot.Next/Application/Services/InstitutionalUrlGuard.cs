namespace AchadinhosBot.Next.Application.Services;

public static class InstitutionalUrlGuard
{
    public static bool ShouldPreserve(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (string.Equals(uri.Host, "bio.reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var path = uri.AbsolutePath;
        return path.StartsWith("/bio", StringComparison.OrdinalIgnoreCase)
               || path.StartsWith("/catalogo", StringComparison.OrdinalIgnoreCase)
               || path.StartsWith("/dashboard", StringComparison.OrdinalIgnoreCase)
               || path.StartsWith("/api", StringComparison.OrdinalIgnoreCase)
               || path.StartsWith("/assets", StringComparison.OrdinalIgnoreCase);
    }
}
