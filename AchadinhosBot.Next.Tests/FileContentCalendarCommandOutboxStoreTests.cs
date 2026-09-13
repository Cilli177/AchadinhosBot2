using System.Text.Json;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Infrastructure.Resilience;

namespace AchadinhosBot.Next.Tests;

public sealed class FileContentCalendarCommandOutboxStoreTests
{
    [Fact]
    public async Task ListPendingAsync_QuarantinesInvalidEnvelope_AndReturnsValidEnvelope()
    {
        var root = Path.Combine(Path.GetTempPath(), "achadinhos-calendar-outbox", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileContentCalendarCommandOutboxStore(root);
            var messageId = Guid.NewGuid().ToString("N");
            await store.SaveAsync(new ContentCalendarCommandEnvelope
            {
                MessageId = messageId,
                PayloadJson = JsonSerializer.Serialize(new ProcessContentCalendarDueCommand { MessageId = messageId })
            }, CancellationToken.None);
            await File.WriteAllTextAsync(Path.Combine(root, "corrupted.json"), "not-json");

            var pending = await store.ListPendingAsync(CancellationToken.None);

            var envelope = Assert.Single(pending);
            Assert.Equal(messageId, envelope.MessageId);
            Assert.True(File.Exists(Path.Combine(root, "corrupted.json.invalid")));
            Assert.False(File.Exists(Path.Combine(root, "corrupted.json")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SaveAndDeleteAsync_NormalizeGuidAndPreventUnsafeFileNames()
    {
        var root = Path.Combine(Path.GetTempPath(), "achadinhos-calendar-outbox", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileContentCalendarCommandOutboxStore(root);
            var messageId = Guid.NewGuid().ToString("N");

            await store.SaveAsync(new ContentCalendarCommandEnvelope { MessageId = messageId, PayloadJson = "{}" }, CancellationToken.None);
            await store.DeleteAsync(messageId, CancellationToken.None);

            Assert.Empty(await store.ListPendingAsync(CancellationToken.None));
            await Assert.ThrowsAsync<ArgumentException>(() => store.SaveAsync(new ContentCalendarCommandEnvelope { MessageId = "../unsafe", PayloadJson = "{}" }, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
