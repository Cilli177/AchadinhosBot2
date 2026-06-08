using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Services;

internal static class TrackingAttributionHelper
{
    private const string Unknown = "unknown";

    public static string NormalizeSurface(string? surface, string fallback = Unknown)
    {
        var normalized = (surface ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return fallback;
        }

        return normalized switch
        {
            "bio" or "biohub" or "bio_hub" or "instagram_bio_link" or "biohub_link" => "instagram_bio",
            "catalog" or "catalogo_web" or "catalog_page" => "catalogo",
            "converter" or "site_conversor" => "conversor_web",
            "admin" or "admin_view" or "admin_convert_success" or "admin_open_offer" or "admin_copy_caption" or "admin_copy_converted_link" => "conversor_admin",
            "telegram" or "telegram_channel" => "telegram",
            "whatsapp" or "whatsapp_group" => "whatsapp_grupo",
            "whatsapp_direct" => "whatsapp_dm",
            _ => normalized
        };
    }

    public static string ResolveChannelFromSurface(string? surface)
    {
        var normalized = NormalizeSurface(surface);
        if (normalized.StartsWith("instagram_", StringComparison.Ordinal))
        {
            return "instagram";
        }

        if (normalized.StartsWith("whatsapp_", StringComparison.Ordinal))
        {
            return "whatsapp";
        }

        if (normalized.StartsWith("telegram", StringComparison.Ordinal))
        {
            return "telegram";
        }

        if (normalized.StartsWith("conversor_", StringComparison.Ordinal) ||
            normalized.StartsWith("catalogo", StringComparison.Ordinal))
        {
            return "web";
        }

        return normalized is Unknown ? Unknown : "web";
    }

    public static string NormalizeStore(string? store)
    {
        var normalized = (store ?? string.Empty).Trim();
        return normalized.Length == 0 ? string.Empty : normalized;
    }

    public static string ResolveStorePrefix(string? store)
    {
        var normalized = NormalizeStore(store).ToLowerInvariant();
        if (normalized.Contains("mercado livre", StringComparison.Ordinal) || normalized.Contains("mercadolivre", StringComparison.Ordinal))
        {
            return "ML";
        }

        if (normalized.Contains("amazon", StringComparison.Ordinal))
        {
            return "AM";
        }

        if (normalized.Contains("shopee", StringComparison.Ordinal))
        {
            return "SP";
        }

        if (normalized.Contains("shein", StringComparison.Ordinal))
        {
            return "SH";
        }

        if (normalized.Contains("magazine luiza", StringComparison.Ordinal) || normalized.Contains("magalu", StringComparison.Ordinal))
        {
            return "MG";
        }

        if (normalized.Contains("casas bahia", StringComparison.Ordinal) || normalized.Contains("casasbahia", StringComparison.Ordinal))
        {
            return "CB";
        }

        if (normalized.Contains("americanas", StringComparison.Ordinal))
        {
            return "AC";
        }

        if (normalized.Contains("aliexpress", StringComparison.Ordinal))
        {
            return "AE";
        }

        if (normalized.Contains("kabum", StringComparison.Ordinal))
        {
            return "KB";
        }

        return "LK";
    }

    public static string? NormalizeOptionalToken(string? value, int maxLength = 120)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim();
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength];
    }

    public static string ResolveCompatibilitySource(string? clickSurface, string? originSurface)
    {
        return NormalizeSurface(clickSurface, NormalizeSurface(originSurface));
    }

    public static (string ClickSurface, string ClickChannel) InferClickAttribution(
        string? source,
        string? pageType,
        string? pageUrl,
        string? referrer,
        string? targetUrl,
        string? fallbackSurface)
    {
        var candidates = new[]
        {
            NormalizeOptionalToken(source),
            NormalizeOptionalToken(pageType),
            ExtractSurfaceFromUrl(pageUrl),
            ExtractSurfaceFromUrl(referrer),
            ExtractSurfaceFromUrl(targetUrl),
            NormalizeOptionalToken(fallbackSurface)
        };

        foreach (var candidate in candidates)
        {
            var normalized = NormalizeSurface(candidate ?? string.Empty, string.Empty);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return (normalized, ResolveChannelFromSurface(normalized));
            }
        }

        var fallback = NormalizeSurface(fallbackSurface);
        return (fallback, ResolveChannelFromSurface(fallback));
    }

    public static LinkTrackingCreateRequest NormalizeCreateRequest(LinkTrackingCreateRequest request)
    {
        var normalizedSurface = NormalizeSurface(request.OriginSurface);
        var normalizedChannel = NormalizeOptionalToken(request.OriginChannel) ?? ResolveChannelFromSurface(normalizedSurface);

        return new LinkTrackingCreateRequest
        {
            TargetUrl = NormalizeOptionalToken(request.TargetUrl, 2048) ?? string.Empty,
            Store = NormalizeStore(request.Store),
            OriginChannel = normalizedChannel,
            OriginSurface = normalizedSurface,
            Campaign = NormalizeOptionalToken(request.Campaign),
            OfferId = NormalizeOptionalToken(request.OfferId),
            DraftId = NormalizeOptionalToken(request.DraftId),
            MessageId = NormalizeOptionalToken(request.MessageId)
        };
    }

    private static string? ExtractSurfaceFromUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var host = uri.Host.ToLowerInvariant();
        var path = uri.AbsolutePath.ToLowerInvariant();

        if (host.Contains("instagram", StringComparison.Ordinal) || path.Contains("/bio", StringComparison.Ordinal))
        {
            return "instagram_bio";
        }

        if (path.Contains("/conversor-admin", StringComparison.Ordinal))
        {
            return "conversor_admin";
        }

        if (path.Contains("/conversor", StringComparison.Ordinal))
        {
            return "conversor_web";
        }

        if (path.Contains("/catalogo", StringComparison.Ordinal) || path.Contains("/item/", StringComparison.Ordinal))
        {
            return "catalogo";
        }

        return null;
    }
}
