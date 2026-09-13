using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Services;

public static class CatalogTargetResolver
{
    public static string Resolve(HttpRequest request)
    {
        var host = request.Host.Host ?? string.Empty;
        return host.Contains("-dev.", StringComparison.OrdinalIgnoreCase) || host.StartsWith("achadinhos-dev", StringComparison.OrdinalIgnoreCase)
            ? CatalogTargets.Dev
            : CatalogTargets.Prod;
    }
}
