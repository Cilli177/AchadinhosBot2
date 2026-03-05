using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Services;

public static class ForwardingSafety
{
    public static bool TryGetStrictForwardText(
        ConversionResult result,
        out string strictText,
        out string reason)
    {
        strictText = string.Empty;

        if (!result.Success)
        {
            reason = "conversion_failed";
            return false;
        }

        if (result.ConvertedLinks <= 0)
        {
            reason = "no_affiliate_links";
            return false;
        }

        if (string.IsNullOrWhiteSpace(result.ConvertedText))
        {
            reason = "empty_converted_text";
            return false;
        }

        strictText = result.ConvertedText.Trim();
        reason = "ok";
        return true;
    }
}

