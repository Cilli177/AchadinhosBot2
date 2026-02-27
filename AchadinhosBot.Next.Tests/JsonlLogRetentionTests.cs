using AchadinhosBot.Next.Infrastructure.Storage;

namespace AchadinhosBot.Next.Tests;

public sealed class JsonlLogRetentionTests
{
    [Fact]
    public async Task TrimIfNeededAsync_TrimsToLatestLines_WhenFileExceedsLimits()
    {
        var dir = CreateTempDir();
        var path = Path.Combine(dir, "logs.jsonl");
        try
        {
            var lines = Enumerable.Range(1, 10).Select(i => $"{{\"n\":{i}}}");
            await File.WriteAllLinesAsync(path, lines);

            await JsonlLogRetention.TrimIfNeededAsync(path, maxLines: 4, maxBytes: 32, CancellationToken.None);

            var remaining = await File.ReadAllLinesAsync(path);
            Assert.Equal(4, remaining.Length);
            Assert.Equal("{\"n\":7}", remaining[0]);
            Assert.Equal("{\"n\":10}", remaining[3]);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task TrimIfNeededAsync_DoesNotTrim_WhenFileIsWithinLimits()
    {
        var dir = CreateTempDir();
        var path = Path.Combine(dir, "logs.jsonl");
        try
        {
            var lines = new[] { "{\"n\":1}", "{\"n\":2}" };
            await File.WriteAllLinesAsync(path, lines);

            await JsonlLogRetention.TrimIfNeededAsync(path, maxLines: 10, maxBytes: 1024, CancellationToken.None);

            var remaining = await File.ReadAllLinesAsync(path);
            Assert.Equal(lines, remaining);
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
