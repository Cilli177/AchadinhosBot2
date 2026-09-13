using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Infrastructure.Storage;

namespace AchadinhosBot.Next.Tests;

public sealed class LogSnapshotServiceTests
{
    [Fact]
    public async Task CreatePreparedAsync_CopiesVerifiedAllowlistedFileAndManifest()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-snapshot-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(root);
            var source = Path.Combine(root, "conversion-logs.jsonl");
            await File.WriteAllTextAsync(source, "one\ntwo\n");
            var service = new LogSnapshotService(new LogMaintenanceLockCoordinator(), root);

            var manifest = await service.CreatePreparedAsync(new TestScope("conversion-logs", ["conversion-logs.jsonl"]), CancellationToken.None);

            var snapshotRoot = Path.Combine(root, "log-snapshots", "conversion-logs", manifest.SnapshotId);
            Assert.Equal("prepared", manifest.State);
            Assert.Single(manifest.Files);
            Assert.Equal(2, manifest.Files[0].Lines);
            Assert.True(File.Exists(Path.Combine(snapshotRoot, "manifest.json")));
            Assert.Equal(await File.ReadAllTextAsync(source), await File.ReadAllTextAsync(Path.Combine(snapshotRoot, "conversion-logs.jsonl")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CreatePreparedAsync_RejectsPathTraversalWithoutCreatingSnapshot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-snapshot-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(root);
            var service = new LogSnapshotService(new LogMaintenanceLockCoordinator(), root);

            await Assert.ThrowsAsync<InvalidOperationException>(() => service.CreatePreparedAsync(new TestScope("conversion-logs", ["../outside.jsonl"]), CancellationToken.None));

            Assert.False(Directory.Exists(Path.Combine(root, "log-snapshots", "conversion-logs")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ClearAndRestoreAsync_RestoresExactFileBytes()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-snapshot-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(root);
            var source = Path.Combine(root, "conversion-logs.jsonl");
            var original = "{\"id\":1}\n{\"id\":2}\n";
            await File.WriteAllTextAsync(source, original);
            var service = new LogSnapshotService(new LogMaintenanceLockCoordinator(), root);
            var scope = new TestScope("conversion-logs", ["conversion-logs.jsonl"]);

            var snapshot = await service.ClearWithSnapshotAsync(scope, CancellationToken.None);
            Assert.Equal("cleared", snapshot.State);
            Assert.Equal(string.Empty, await File.ReadAllTextAsync(source));
            await File.WriteAllTextAsync(source, "new-entry\n");

            var preRestore = await service.RestoreAsync(scope, snapshot.SnapshotId, CancellationToken.None);

            Assert.Equal(original, await File.ReadAllTextAsync(source));
            Assert.NotEqual(snapshot.SnapshotId, preRestore.SnapshotId);
            var listed = await service.ListAsync(scope, CancellationToken.None);
            Assert.Equal("restored", listed.Single(item => item.SnapshotId == snapshot.SnapshotId).State);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RestoreAsync_RejectsManifestThatDoesNotCoverTheWholeScope()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-snapshot-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(root);
            var service = new LogSnapshotService(new LogMaintenanceLockCoordinator(root), root);
            var scope = new TestScope("conversion-logs", ["first.jsonl", "second.jsonl"]);
            await File.WriteAllTextAsync(Path.Combine(root, "first.jsonl"), "one\n");
            await File.WriteAllTextAsync(Path.Combine(root, "second.jsonl"), "two\n");
            var snapshot = await service.CreatePreparedAsync(scope, CancellationToken.None);
            var manifestPath = Path.Combine(root, "log-snapshots", scope.ScopeId, snapshot.SnapshotId, "manifest.json");
            var incomplete = snapshot with { Files = [snapshot.Files.Single(file => file.RelativePath == "first.jsonl")] };
            await File.WriteAllTextAsync(manifestPath, incomplete.ToJson());

            await Assert.ThrowsAsync<InvalidOperationException>(() => service.RestoreAsync(scope, snapshot.SnapshotId, CancellationToken.None));
            Assert.Equal("one\n", await File.ReadAllTextAsync(Path.Combine(root, "first.jsonl")));
            Assert.Equal("two\n", await File.ReadAllTextAsync(Path.Combine(root, "second.jsonl")));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private sealed record TestScope(string ScopeId, IReadOnlyList<string> RelativePaths) : ILogMaintenanceScope;
}
