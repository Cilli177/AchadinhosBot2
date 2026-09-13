using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class LogSnapshotRetentionServiceTests
{
    [Fact]
    public async Task PruneAsync_KeepsMinimumAndRemovesSnapshotsPastPerScopeLimit()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-retention-{Guid.NewGuid():N}");
        try
        {
            for (var index = 0; index < 5; index++)
                await CreateSnapshotAsync(root, "conversion-logs", DateTimeOffset.UtcNow.AddMinutes(-index));

            var retention = CreateService(root, maxPerScope: 3, maxBytes: 1024 * 1024);
            await retention.PruneAsync(CancellationToken.None);

            var snapshots = Directory.EnumerateDirectories(Path.Combine(root, "log-snapshots", "conversion-logs")).ToArray();
            Assert.Equal(3, snapshots.Length);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task EnsureCapacityForSnapshotAsync_BlocksBeforeAWriteWouldExceedQuota()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-retention-{Guid.NewGuid():N}");
        try
        {
            await CreateSnapshotAsync(root, "conversion-logs", DateTimeOffset.UtcNow, bytes: 20);
            var retention = CreateService(root, maxPerScope: 3, maxBytes: 25);

            await Assert.ThrowsAsync<InvalidOperationException>(() => retention.EnsureCapacityForSnapshotAsync(10, CancellationToken.None));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private static LogSnapshotRetentionService CreateService(string root, int maxPerScope, long maxBytes) => new(
        Options.Create(new LogSnapshotRetentionOptions { MaxSnapshotsPerScope = maxPerScope, MinimumSnapshotsPerScope = 3, MaxTotalBytes = maxBytes, RetentionDays = 30 }),
        NullLogger<LogSnapshotRetentionService>.Instance,
        root);

    private static async Task CreateSnapshotAsync(string root, string scope, DateTimeOffset created, int bytes = 1)
    {
        var id = SnapshotManifest.CreateSnapshotId();
        var directory = Path.Combine(root, "log-snapshots", scope, id);
        Directory.CreateDirectory(directory);
        var payload = new string('x', bytes);
        await File.WriteAllTextAsync(Path.Combine(directory, "events.jsonl"), payload);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        var manifest = new SnapshotManifest(id, scope, created, "prepared", [new SnapshotFileEntry("events.jsonl", bytes, 1, hash)]);
        await File.WriteAllTextAsync(Path.Combine(directory, "manifest.json"), manifest.ToJson());
        await Task.Delay(2);
    }
}
