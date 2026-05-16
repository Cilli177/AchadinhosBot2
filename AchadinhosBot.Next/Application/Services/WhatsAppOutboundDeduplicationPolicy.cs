using AchadinhosBot.Next.Configuration;

namespace AchadinhosBot.Next.Application.Services;

public static class WhatsAppOutboundDeduplicationPolicy
{
    public static TimeSpan ResolveWindow(bool isOfficialDestination, MessagingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (isOfficialDestination)
        {
            var hours = Math.Clamp(options.OfficialOfferRepeatWindowHours, 24, 720);
            return TimeSpan.FromHours(hours);
        }

        var seconds = Math.Clamp(options.OutboundDeduplicationWindowSeconds, 30, 86400);
        return TimeSpan.FromSeconds(seconds);
    }
}
