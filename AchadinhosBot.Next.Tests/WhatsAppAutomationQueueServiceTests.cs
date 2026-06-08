using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppAutomationQueueServiceTests
{
    [Fact]
    public async Task ProcessNextAsync_DoesNotLetFutureScheduledItemBlockImmediateItem()
    {
        var queue = new WhatsAppAutomationQueueService();
        var processed = new List<string>();

        await queue.EnqueueAsync(
            "future",
            "Future",
            _ =>
            {
                processed.Add("future");
                return Task.FromResult((true, "ok"));
            },
            CancellationToken.None,
            DateTimeOffset.UtcNow.AddMinutes(10));

        await queue.EnqueueAsync(
            "now",
            "Now",
            _ =>
            {
                processed.Add("now");
                return Task.FromResult((true, "ok"));
            },
            CancellationToken.None);

        Assert.True(queue.HasDueQueuedWork());
        await queue.ProcessNextAsync(CancellationToken.None);

        Assert.Equal(new[] { "now" }, processed);
        Assert.False(queue.HasDueQueuedWork());
        Assert.Contains(queue.GetState().Items, x => x.Kind == "future" && x.Status == "queued" && x.ScheduledForUtc.HasValue);
    }

    [Fact]
    public async Task ProcessNextAsync_RequeuesTransientRateLimitFailureWithBackoff()
    {
        var queue = new WhatsAppAutomationQueueService(new DefaultOutboundRateLimitPolicy());
        var attempts = 0;

        await queue.EnqueueAsync(
            "whatsapp",
            "120363405661434395@g.us",
            _ =>
            {
                attempts++;
                return Task.FromResult((false, "429 rate limit"));
            },
            CancellationToken.None);

        await queue.ProcessNextAsync(CancellationToken.None);

        var item = Assert.Single(queue.GetState().Items);
        Assert.Equal(1, attempts);
        Assert.Equal("queued", item.Status);
        Assert.Equal(1, item.Attempts);
        Assert.Equal("429 rate limit", item.LastError);
        Assert.True(item.ScheduledForUtc > DateTimeOffset.UtcNow);
    }
}
