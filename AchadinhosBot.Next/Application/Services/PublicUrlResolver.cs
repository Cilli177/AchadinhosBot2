using System.Text.Json;

namespace AchadinhosBot.Next.Application.Services;

/// <summary>Single source of truth for public URL normalization and hosted-media URLs.</summary>
public static class PublicUrlResolver
{
    public static string Resolve(string? primaryPublicBaseUrl, string? secondaryPublicBaseUrl, string requestScheme, string requestHost)
    {
        if (TryNormalize(primaryPublicBaseUrl, out var primary)) return primary;
        if (TryNormalize(secondaryPublicBaseUrl, out var secondary)) return secondary;
        if (TryReadBundled(out var bundled)) return bundled;
        if (string.IsNullOrWhiteSpace(requestHost)) return string.Empty;
        var scheme = string.IsNullOrWhiteSpace(requestScheme) ? "https" : requestScheme.Trim();
        return $"{scheme}://{requestHost}".TrimEnd('/');
    }

    public static bool TryNormalize(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var trimmed = value.Trim().TrimEnd('/');
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)) return false;
        if (!string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase) && !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase)) return false;
        if (uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase) || uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            normalized = $"{uri.Scheme}://reidasofertas.ia.br";
            return true;
        }
        normalized = uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        return !string.IsNullOrWhiteSpace(normalized);
    }

    public static bool IsInternalLikeHost(string host)
    {
        var normalized = (host ?? string.Empty).Trim().ToLowerInvariant();
        return normalized is "localhost" or "127.0.0.1" or "0.0.0.0" or "host.docker.internal" or "host.internal" or "docker.internal"
            || normalized.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
            || normalized.EndsWith(".internal", StringComparison.OrdinalIgnoreCase);
    }

    public static string BuildMediaUrl(string publicBaseUrl, string id)
    {
        var url = publicBaseUrl.TrimEnd('/') + $"/media/{id}.jpg";
        return url.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) || url.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase)
            ? url + "?ngrok-skip-browser-warning=1"
            : url;
    }

    private static bool TryReadBundled(out string publicBaseUrl)
    {
        publicBaseUrl = string.Empty;
        var file = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(file)) return false;
        try
        {
            using var stream = File.OpenRead(file);
            using var doc = JsonDocument.Parse(stream);
            if (doc.RootElement.TryGetProperty("Webhook", out var webhook) && webhook.ValueKind == JsonValueKind.Object && webhook.TryGetProperty("PublicBaseUrl", out var baseUrlProp) && TryNormalize(baseUrlProp.GetString(), out var normalized))
            {
                publicBaseUrl = normalized;
                return true;
            }
        }
        catch { }
        return false;
    }
}
