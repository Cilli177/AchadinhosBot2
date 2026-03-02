using AchadinhosBot.Next.Infrastructure.Media;

namespace AchadinhosBot.Next.Tests;

public sealed class FileMediaStoreTests
{
    [Fact]
    public void AddAndTryGet_RoundTripsMedia()
    {
        var dir = CreateTempDir();
        try
        {
            var store = new FileMediaStore(dir);
            var payload = new byte[] { 1, 2, 3, 4 };

            var id = store.Add(payload, "image/jpeg", TimeSpan.FromMinutes(5));
            var ok = store.TryGet(id, out var item);

            Assert.True(ok);
            Assert.Equal("image/jpeg", item.MimeType);
            Assert.Equal(payload, item.Bytes);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void TryGet_WorksAfterRestart_ForUnexpiredMedia()
    {
        var dir = CreateTempDir();
        try
        {
            var store = new FileMediaStore(dir);
            var payload = new byte[] { 7, 8, 9 };
            var id = store.Add(payload, "image/png", TimeSpan.FromMinutes(5));

            var restarted = new FileMediaStore(dir);
            var ok = restarted.TryGet(id, out var item);

            Assert.True(ok);
            Assert.Equal("image/png", item.MimeType);
            Assert.Equal(payload, item.Bytes);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void TryGet_ReturnsFalse_ForExpiredMedia()
    {
        var dir = CreateTempDir();
        try
        {
            var store = new FileMediaStore(dir);
            var id = store.Add(new byte[] { 1 }, "application/octet-stream", TimeSpan.FromMilliseconds(10));
            Thread.Sleep(60);

            var ok = store.TryGet(id, out _);

            Assert.False(ok);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "achadinhos-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
