using AchadinhosBot.Next.Domain.Logs;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public sealed class OperationalStatusServiceTests
{
    [Fact]
    public void IsActualMediaFailure_ShouldReturnFalse_WhenEntryWasSuccessful()
    {
        var entry = new MediaFailureEntry
        {
            Success = true,
            Reason = "image_sent_hosted_url"
        };

        var result = OperationalStatusService.IsActualMediaFailure(entry);

        Assert.False(result);
    }

    [Fact]
    public void IsActualMediaFailure_ShouldReturnTrue_WhenEntryFailed()
    {
        var entry = new MediaFailureEntry
        {
            Success = false,
            Reason = "image_send_failed"
        };

        var result = OperationalStatusService.IsActualMediaFailure(entry);

        Assert.True(result);
    }
}
