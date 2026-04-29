namespace AchadinhosBot.Next.Application.Services;

internal static class WhatsAppForwardMediaHelper
{
    public static bool ShouldPreferLinkPreviewWithoutMedia(bool hasMediaCandidate, bool preferLinkPreviewWhenNoMedia)
        => !hasMediaCandidate && preferLinkPreviewWhenNoMedia;

    public static T BuildOutboundMediaMessage<T>(
        T original,
        string? fallbackImageUrl,
        Func<T, bool> hasMediaSelector,
        Func<T, string, T> normalizeForFallback)
    {
        if (hasMediaSelector(original) ||
            string.IsNullOrWhiteSpace(fallbackImageUrl))
        {
            return original;
        }

        return normalizeForFallback(original, fallbackImageUrl.Trim());
    }

    public static string ResolveMediaFileName(string? mimeType)
        => (mimeType ?? string.Empty).ToLowerInvariant() switch
        {
            "image/png" => "offer.png",
            "image/webp" => "offer.webp",
            "image/gif" => "offer.gif",
            _ => "offer.jpg"
        };
}
