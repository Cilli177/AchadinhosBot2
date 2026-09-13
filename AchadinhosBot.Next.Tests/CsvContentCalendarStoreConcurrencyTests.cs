using AchadinhosBot.Next.Domain.Content;
using AchadinhosBot.Next.Infrastructure.Storage;

namespace AchadinhosBot.Next.Tests;

public sealed class CsvContentCalendarStoreConcurrencyTests
{
    [Fact]
    public async Task ExportedCsv_WithMultilineCaption_CanBeReadWithoutDataLoss()
    {
        var root = Path.Combine(Path.GetTempPath(), "achadinhos-calendar-csv-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(root, "content-calendar.csv");
        try
        {
            var store = new CsvContentCalendarStore(path);
            var item = new ContentCalendarItem
            {
                Id = "multiline-caption",
                GeneratedCaption = "Primeira linha\nSegunda linha",
                ScheduledAt = DateTimeOffset.UtcNow
            };

            await store.SaveAsync(item, CancellationToken.None);

            var restored = await store.GetAsync(item.Id, CancellationToken.None);

            Assert.NotNull(restored);
            Assert.Equal(item.GeneratedCaption, restored!.GeneratedCaption);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task TryClaimDueAsync_WithSeparateStoreInstances_AllowsOnlyOneClaim()
    {
        var root = Path.Combine(Path.GetTempPath(), "achadinhos-calendar-lock-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(root, "content-calendar.csv");
        try
        {
            var first = new CsvContentCalendarStore(path);
            var second = new CsvContentCalendarStore(path);
            var item = new ContentCalendarItem { Id = "due-item", ScheduledAt = DateTimeOffset.UtcNow.AddMinutes(-1), Status = "planned" };
            await first.SaveAsync(item, CancellationToken.None);

            var now = DateTimeOffset.UtcNow;
            var claims = await Task.WhenAll(
                first.TryClaimDueAsync(item.Id, "run-a", now, 3, CancellationToken.None),
                second.TryClaimDueAsync(item.Id, "run-b", now, 3, CancellationToken.None));

            var claimed = Assert.Single(claims.Where(x => x is not null));
            Assert.Equal("processing", claimed!.Status);
            Assert.Equal(1, claimed.Attempts);
            var saved = await first.GetAsync(item.Id, CancellationToken.None);
            Assert.Equal(claimed.ProcessingExecutionId, saved!.ProcessingExecutionId);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
