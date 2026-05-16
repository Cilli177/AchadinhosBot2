using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Application.Services;

public static class TelegramReelDraftSelectionHelper
{
    public static TelegramUserbotOfferMessage? SelectLatestEligibleOffer(
        IReadOnlyList<TelegramUserbotOfferMessage> offers,
        string? messageId = null,
        bool requireMediaUrl = true)
    {
        if (offers is null || offers.Count == 0)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(messageId))
        {
            var requested = offers.FirstOrDefault(x => string.Equals(x.MessageId, messageId, StringComparison.OrdinalIgnoreCase));
            if (requested is not null)
            {
                return IsEligibleOffer(requested, requireMediaUrl) ? requested : null;
            }
        }

        foreach (var offer in offers.OrderByDescending(x => x.CreatedAtUtc).ThenByDescending(x => x.MessageId, StringComparer.OrdinalIgnoreCase))
        {
            if (!IsEligibleOffer(offer, requireMediaUrl))
            {
                continue;
            }

            return offer;
        }

        return null;
    }

    public static IReadOnlyList<TelegramUserbotOfferMessage> SelectEligibleOffers(
        IReadOnlyList<TelegramUserbotOfferMessage> offers,
        bool requireMediaUrl = true)
    {
        if (offers is null || offers.Count == 0)
        {
            return Array.Empty<TelegramUserbotOfferMessage>();
        }

        return offers
            .Where(x => IsEligibleOffer(x, requireMediaUrl))
            .OrderByDescending(x => x.CreatedAtUtc)
            .ThenByDescending(x => x.MessageId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static bool IsEligibleOffer(TelegramUserbotOfferMessage offer, bool requireMediaUrl = true)
    {
        if (!string.Equals(offer.MediaKind, "video", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (requireMediaUrl && string.IsNullOrWhiteSpace(offer.MediaUrl))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(ExtractFirstUrl(offer.Text)))
        {
            return false;
        }

        return !TryGetBlockedReason(offer.Text, out _);
    }

    public static bool TryGetBlockedReason(string? text, out string reason)
    {
        reason = string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var normalized = Regex.Replace(text, @"\s+", " ", RegexOptions.CultureInvariant).Trim();
        if (normalized.Contains("cupom radar", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("automatize 100%", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("modo fila", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("utilize até 10 postagens por dia gratuitamente", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("faca seu cadastro agora mesmo", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("faça seu cadastro agora mesmo", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("top afiliados", StringComparison.OrdinalIgnoreCase))
        {
            reason = "manual_blocked_cupom_radar";
            return true;
        }

        var url = ExtractFirstUrl(text);
        if (!string.IsNullOrWhiteSpace(url) &&
            Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            uri.Host.Contains("cupomradaroficial.com", StringComparison.OrdinalIgnoreCase))
        {
            reason = "manual_blocked_cupom_radar";
            return true;
        }

        return false;
    }

    public static string? ExtractFirstUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var index = text.IndexOf("http://", StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            index = text.IndexOf("https://", StringComparison.OrdinalIgnoreCase);
        }

        if (index < 0)
        {
            return null;
        }

        var candidate = text[index..].Trim();
        var end = candidate.IndexOfAny([' ', '\r', '\n', '\t']);
        if (end >= 0)
        {
            candidate = candidate[..end];
        }

        return candidate.Trim().TrimEnd('.', ',', ';', ')', ']', '>');
    }
}
