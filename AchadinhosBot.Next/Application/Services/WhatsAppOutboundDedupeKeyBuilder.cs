using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Application.Services;

public static partial class WhatsAppOutboundDedupeKeyBuilder
{
    public static async Task<string> BuildAsync(
        string? instanceName,
        string destination,
        string text,
        bool hasMedia,
        bool isOfficialDestination,
        ILinkTrackingStore linkTrackingStore,
        CancellationToken ct)
    {
        var normalizedInstance = string.IsNullOrWhiteSpace(instanceName) ? "default" : instanceName.Trim();
        var normalizedDestination = string.IsNullOrWhiteSpace(destination) ? "unknown" : destination.Trim();
        var fingerprint = isOfficialDestination
            ? await TryBuildOfficialOfferFingerprintAsync(text, linkTrackingStore, ct)
            : null;
        var normalizedContent = string.IsNullOrWhiteSpace(fingerprint)
            ? Regex.Replace(text ?? string.Empty, "\\s+", " ").Trim()
            : fingerprint;
        var payload = $"{normalizedInstance}|{normalizedDestination}|{(hasMedia ? "img" : "txt")}|{normalizedContent}";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        return $"wa-outbound:{normalizedInstance}:{normalizedDestination}:{hash}";
    }

    private static async Task<string?> TryBuildOfficialOfferFingerprintAsync(
        string text,
        ILinkTrackingStore linkTrackingStore,
        CancellationToken ct)
    {
        foreach (Match match in OfficialTrackingUrlRegex().Matches(text ?? string.Empty))
        {
            var resolved = TrackingIdDecorator.Resolve(match.Groups["id"].Value);
            var tracking = await linkTrackingStore.GetLinkAsync(resolved.LookupId, ct);
            if (!string.IsNullOrWhiteSpace(tracking?.TargetUrl))
            {
                return $"target:{NormalizeTargetUrl(tracking.TargetUrl)}";
            }
        }

        return null;
    }

    private static string NormalizeTargetUrl(string targetUrl)
        => targetUrl.Trim();

    [GeneratedRegex(@"https?://[^\s]+/r/(?<id>[^/?#\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OfficialTrackingUrlRegex();
}
