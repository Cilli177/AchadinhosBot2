using AchadinhosBot.Next.Infrastructure.Storage;

namespace AchadinhosBot.Next.Tests;

public sealed class VersionRetentionPolicyTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(
        Path.GetTempPath(),
        "achadinhos-version-retention-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Prune_ShouldKeepNewestNonEmptyFilesAndDeleteZeroByteSnapshots()
    {
        Directory.CreateDirectory(_tempDir);

        for (var i = 0; i < 5; i++)
        {
            var path = Path.Combine(_tempDir, $"link-tracking.{i:000}.json.bak");
            File.WriteAllText(path, i == 4 ? string.Empty : $"backup-{i}");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(i));
        }

        VersionRetentionPolicy.Prune(_tempDir, "link-tracking.*.json.bak", 2);

        var remaining = Directory.GetFiles(_tempDir, "link-tracking.*.json.bak")
            .Select(Path.GetFileName)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Equal(
            new[]
            {
                "link-tracking.002.json.bak",
                "link-tracking.003.json.bak"
            },
            remaining);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
