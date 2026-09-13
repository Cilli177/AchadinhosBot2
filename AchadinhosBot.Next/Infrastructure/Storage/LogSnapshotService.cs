using System.Security.Cryptography;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Storage;

/// <summary>Creates self-contained, verified snapshots without exposing snapshot paths to callers.</summary>
internal sealed class LogSnapshotService
{
    private readonly ILogMaintenanceLockCoordinator _locks;
    private readonly LogSnapshotRetentionService _retention;
    private readonly string _dataRoot;

    internal LogSnapshotService(ILogMaintenanceLockCoordinator locks, string? dataRoot = null)
        : this(locks, new LogSnapshotRetentionService(Options.Create(new LogSnapshotRetentionOptions()), NullLogger<LogSnapshotRetentionService>.Instance, dataRoot), dataRoot)
    {
    }

    internal LogSnapshotService(ILogMaintenanceLockCoordinator locks, LogSnapshotRetentionService retention, string? dataRoot = null)
    {
        _locks = locks;
        _retention = retention;
        _dataRoot = Path.GetFullPath(dataRoot ?? Path.Combine(AppContext.BaseDirectory, "data"));
    }

    internal async Task<SnapshotManifest> CreatePreparedAsync(ILogMaintenanceScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (string.IsNullOrWhiteSpace(scope.ScopeId) || scope.RelativePaths.Count == 0)
            throw new InvalidOperationException("A maintenance scope must declare allowlisted files.");

        // Validate every client-independent allowlisted path before any filesystem side effect.
        foreach (var relativePath in scope.RelativePaths)
            _ = ResolveAllowlistedPath(relativePath);

        await using var held = await _locks.AcquireAsync(scope.ScopeId, cancellationToken);
        await _retention.EnsureCapacityForSnapshotAsync(EstimateSourceBytes(scope), cancellationToken);
        return await CreatePreparedUnderLockAsync(scope, cancellationToken);
    }

    internal async Task<SnapshotManifest> ClearWithSnapshotAsync(ILogMaintenanceScope scope, CancellationToken cancellationToken)
    {
        ValidateScope(scope);
        await using var held = await _locks.AcquireAsync(scope.ScopeId, cancellationToken);
        await _retention.EnsureCapacityForSnapshotAsync(EstimateSourceBytes(scope), cancellationToken);
        var snapshot = await CreatePreparedUnderLockAsync(scope, cancellationToken);
        foreach (var relativePath in scope.RelativePaths)
            await File.WriteAllBytesAsync(ResolveAllowlistedPath(relativePath), [], cancellationToken);
        return await UpdateStateAsync(snapshot, "cleared", cancellationToken);
    }

    internal async Task<SnapshotManifest> RestoreAsync(ILogMaintenanceScope scope, string snapshotId, CancellationToken cancellationToken)
    {
        ValidateScope(scope);
        if (!SnapshotManifest.IsValidSnapshotId(snapshotId))
            throw new InvalidOperationException("Invalid snapshot id.");

        await using var held = await _locks.AcquireAsync(scope.ScopeId, cancellationToken);
        var snapshotRoot = Path.Combine(_dataRoot, "log-snapshots", scope.ScopeId, snapshotId);
        var manifestPath = Path.Combine(snapshotRoot, "manifest.json");
        if (!File.Exists(manifestPath))
            throw new FileNotFoundException("Snapshot manifest was not found.");

        var manifest = SnapshotManifest.FromJson(await File.ReadAllTextAsync(manifestPath, cancellationToken));
        ValidateManifest(scope, snapshotId, manifest);
        var validatedManifest = manifest!;

        var preRestoreSnapshot = await CreatePreparedUnderLockAsync(scope, cancellationToken);

        foreach (var entry in validatedManifest.Files)
        {
            var target = ResolveAllowlistedPath(entry.RelativePath);
            if (!entry.Exists)
            {
                if (File.Exists(target)) File.Delete(target);
                continue;
            }
            var snapshotFile = Path.GetFullPath(Path.Combine(snapshotRoot, entry.RelativePath));
            if (!snapshotFile.StartsWith(snapshotRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !File.Exists(snapshotFile))
                throw new InvalidOperationException("Snapshot file is invalid.");
            var bytes = await File.ReadAllBytesAsync(snapshotFile, cancellationToken);
            if (bytes.LongLength != entry.Bytes || !string.Equals(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), entry.Sha256, StringComparison.Ordinal))
                throw new InvalidOperationException("Snapshot integrity check failed.");

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            var temporaryTarget = target + ".restore.tmp";
            await File.WriteAllBytesAsync(temporaryTarget, bytes, cancellationToken);
            File.Move(temporaryTarget, target, overwrite: true);
        }
        await UpdateStateAsync(validatedManifest, "restored", cancellationToken);
        return preRestoreSnapshot;
    }

    internal async Task<IReadOnlyList<SnapshotManifest>> ListAsync(ILogMaintenanceScope scope, CancellationToken cancellationToken)
    {
        ValidateScope(scope);
        await using var held = await _locks.AcquireAsync(scope.ScopeId, cancellationToken);
        var scopeDirectory = Path.Combine(_dataRoot, "log-snapshots", scope.ScopeId);
        if (!Directory.Exists(scopeDirectory)) return [];
        var snapshots = new List<SnapshotManifest>();
        foreach (var directory in Directory.EnumerateDirectories(scopeDirectory))
        {
            var snapshotId = Path.GetFileName(directory);
            var manifestPath = Path.Combine(directory, "manifest.json");
            if (!File.Exists(manifestPath) || !SnapshotManifest.IsValidSnapshotId(snapshotId)) continue;
            try
            {
                var manifest = SnapshotManifest.FromJson(await File.ReadAllTextAsync(manifestPath, cancellationToken));
                ValidateManifest(scope, snapshotId, manifest);
                snapshots.Add(manifest!);
            }
            catch (InvalidOperationException) { }
            catch (System.Text.Json.JsonException) { }
        }
        return snapshots.OrderByDescending(static snapshot => snapshot.CreatedAtUtc).ToArray();
    }

    private async Task<SnapshotManifest> CreatePreparedUnderLockAsync(ILogMaintenanceScope scope, CancellationToken cancellationToken)
    {
        ValidateScope(scope);
        var snapshotId = SnapshotManifest.CreateSnapshotId();
        var snapshotsRoot = Path.Combine(_dataRoot, "log-snapshots", scope.ScopeId, snapshotId);
        var temporaryRoot = snapshotsRoot + ".tmp";
        Directory.CreateDirectory(temporaryRoot);

        try
        {
            var entries = new List<SnapshotFileEntry>();
            foreach (var relativePath in scope.RelativePaths.OrderBy(static path => path, StringComparer.Ordinal))
            {
                var sourcePath = ResolveAllowlistedPath(relativePath);
                if (!File.Exists(sourcePath))
                {
                    entries.Add(new SnapshotFileEntry(relativePath, 0, 0, string.Empty, Exists: false));
                    continue;
                }

                var destinationPath = Path.Combine(temporaryRoot, relativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
                File.Copy(sourcePath, destinationPath, overwrite: false);

                var bytes = await File.ReadAllBytesAsync(destinationPath, cancellationToken);
                var lines = await CountLinesAsync(destinationPath, cancellationToken);
                entries.Add(new SnapshotFileEntry(relativePath, bytes.LongLength, lines, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()));
            }

            var manifest = new SnapshotManifest(snapshotId, scope.ScopeId, DateTimeOffset.UtcNow, "prepared", entries);
            var manifestTemporaryPath = Path.Combine(temporaryRoot, "manifest.json.tmp");
            await File.WriteAllTextAsync(manifestTemporaryPath, manifest.ToJson(), cancellationToken);
            File.Move(manifestTemporaryPath, Path.Combine(temporaryRoot, "manifest.json"));
            Directory.Move(temporaryRoot, snapshotsRoot);
            return manifest;
        }
        catch
        {
            if (Directory.Exists(temporaryRoot))
                Directory.Delete(temporaryRoot, recursive: true);
            throw;
        }
    }

    private void ValidateScope(ILogMaintenanceScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (string.IsNullOrWhiteSpace(scope.ScopeId) || scope.RelativePaths.Count == 0)
            throw new InvalidOperationException("A maintenance scope must declare allowlisted files.");
        foreach (var relativePath in scope.RelativePaths)
            _ = ResolveAllowlistedPath(relativePath);
    }

    private static void ValidateManifest(ILogMaintenanceScope scope, string snapshotId, SnapshotManifest? manifest)
    {
        if (manifest is null || manifest.SnapshotId != snapshotId || manifest.ScopeId != scope.ScopeId || manifest.State is not ("prepared" or "cleared" or "restored"))
            throw new InvalidOperationException("Snapshot manifest is invalid.");
        var expected = scope.RelativePaths.OrderBy(static path => path, StringComparer.Ordinal).ToArray();
        var actual = manifest.Files.Select(static file => file.RelativePath).OrderBy(static path => path, StringComparer.Ordinal).ToArray();
        if (actual.Length != actual.Distinct(StringComparer.Ordinal).Count() || !expected.SequenceEqual(actual, StringComparer.Ordinal))
            throw new InvalidOperationException("Snapshot manifest does not match the requested scope.");
    }

    private string ResolveAllowlistedPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || Path.IsPathRooted(relativePath) || relativePath.Contains("..", StringComparison.Ordinal))
            throw new InvalidOperationException("Snapshot paths must be relative and allowlisted.");

        var path = Path.GetFullPath(Path.Combine(_dataRoot, relativePath));
        if (!path.StartsWith(_dataRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Snapshot path escapes the data root.");
        return path;
    }

    private async Task<SnapshotManifest> UpdateStateAsync(SnapshotManifest manifest, string state, CancellationToken cancellationToken)
    {
        var updated = manifest with { State = state };
        var path = Path.Combine(_dataRoot, "log-snapshots", manifest.ScopeId, manifest.SnapshotId, "manifest.json");
        var temporary = path + ".state.tmp";
        await File.WriteAllTextAsync(temporary, updated.ToJson(), cancellationToken);
        File.Move(temporary, path, overwrite: true);
        return updated;
    }

    private static async Task<long> CountLinesAsync(string path, CancellationToken cancellationToken)
    {
        long count = 0;
        using var reader = new StreamReader(path);
        while (await reader.ReadLineAsync(cancellationToken) is not null)
            count++;
        return count;
    }

    private long EstimateSourceBytes(ILogMaintenanceScope scope) => scope.RelativePaths
        .Select(ResolveAllowlistedPath)
        .Where(File.Exists)
        .Sum(path => new FileInfo(path).Length);
}
