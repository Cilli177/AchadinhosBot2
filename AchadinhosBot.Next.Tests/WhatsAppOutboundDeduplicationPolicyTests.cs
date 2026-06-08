using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppOutboundDeduplicationPolicyTests
{
    [Fact]
    public void ResolveWindow_ShouldUseOfficialRepeatWindow_ForOfficialDestination()
    {
        var options = new MessagingOptions
        {
            OutboundDeduplicationWindowSeconds = 300,
            OfficialOfferRepeatWindowHours = 24
        };

        var result = WhatsAppOutboundDeduplicationPolicy.ResolveWindow(true, options);

        Assert.Equal(TimeSpan.FromHours(24), result);
    }

    [Fact]
    public void ResolveWindow_ShouldUseDefaultOutboundWindow_ForNonOfficialDestination()
    {
        var options = new MessagingOptions
        {
            OutboundDeduplicationWindowSeconds = 300,
            OfficialOfferRepeatWindowHours = 24
        };

        var result = WhatsAppOutboundDeduplicationPolicy.ResolveWindow(false, options);

        Assert.Equal(TimeSpan.FromMinutes(5), result);
    }
}
