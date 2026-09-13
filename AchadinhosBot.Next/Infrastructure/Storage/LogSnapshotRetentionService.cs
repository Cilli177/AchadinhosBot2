using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Storage;

internal sealed class LogSnapshotRetentionService
{
    private readonly LogSnapshotRetentionOptions _options;
    private readonly string _snapshotsRoot;
    private readonly ILogger<LogSnapshotRetentionService> _logger;

    internal LogSnapshotRetentionService(IOptions<LogSnapshotRetentionOptions> options, ILogger<LogSnapshotRetentionService> logger, string? dataRoot = null)
    {
        _options = options.Value;
        _logger = logger;
        _snapshotsRoot = Path.Combine(Path.GetFullPath(dataRoot ?? Path.Combine(AppContext.BaseDirectory, "data")), "log-snapshots");
    }

    internal async Task EnsureCapacityForSnapshotAsync(long projectedBytes, CancellationToken cancellationToken)
    {
        if (projectedBytes < 0) throw new ArgumentOutOfRangeException(nameof(projectedBytes));
        var total = await PruneAsync(cancellationToken);
        if (total + projectedBytes > _options.MaxTotalBytes)
            throw new InvalidOperationException("Snapshot storage quota has been reached; no logs were changed.");
    }

    internal async Task<long> PruneAsync(CancellationToken cancellationToken)
    {
        var snapshots = await LoadValidatedSnapshotsAsync(cancellationToken);
        var protectedIds = snapshots.GroupBy(x => x.ScopeId, StringComparer.Ordinal)
            .SelectMany(group => group.OrderByDescending(x => x.CreatedAtUtc).Take(Math.Max(0, _options.MinimumSnapshotsPerScope)).Select(x => x.DirectoryPath))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var cutoff = DateTimeOffset.UtcNow.AddDays(-Math.Max(0, _options.RetentionDays));

        foreach (var scope in snapshots.GroupBy(x => x.ScopeId, StringComparer.Ordinal))
        {
            var ordered = scope.OrderByDescending(x => x.CreatedAtUtc).ToArray();
            for (var index = 0; index < ordered.Length; index++)
            {
                var item = ordered[index];
                if (protectedIds.Contains(item.DirectoryPath)) continue;
                if (index >= Math.Max(_options.MaxSnapshotsPerScope, _options.MinimumSnapshotsPerScope) || item.CreatedAtUtc < cutoff)
                    DeleteSnapshot(item);
            }
        }

        snapshots = await LoadValidatedSnapshotsAsync(cancellationToken);
        var total = snapshots.Sum(x => x.Bytes);
        if (total >= _options.MaxTotalBytes * _options.WarningPercent / 100)
            _logger.LogWarning("Log snapshot storage is at {Bytes} bytes of {Limit} bytes.", total, _options.MaxTotalBytes);

        foreach (var item in snapshots.OrderBy(x => x.CreatedAtUtc))
        {
            if (total <= _options.MaxTotalBytes || protectedIds.Contains(item.DirectoryPath)) continue;
            DeleteSnapshot(item);
            total -= item.Bytes;
        }

        return total;
    }

    private async Task<List<SnapshotInfo>> LoadValidatedSnapshotsAsync(CancellationToken cancellationToken)
    {
        var result = new List<SnapshotInfo>();
        if (!Directory.Exists(_snapshotsRoot)) return result;
        foreach (var scopeDirectory in Directory.EnumerateDirectories(_snapshotsRoot))
        foreach (var snapshotDirectory in Directory.EnumerateDirectories(scopeDirectory))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var manifestPath = Path.Combine(snapshotDirectory, "manifest.json");
            try
            {
                if (!File.Exists(manifestPath)) continue;
                var manifest = SnapshotManifest.FromJson(await File.ReadAllTextAsync(manifestPath, cancellationToken));
                if (manifest is null || manifest.State is not ("prepared" or "cleared" or "restored") || !SnapshotManifest.IsValidSnapshotId(manifest.SnapshotId) ||
                    !string.Equals(manifest.ScopeId, Path.GetFileName(scopeDirectory), StringComparison.Ordinal) ||
                    !string.Equals(manifest.SnapshotId, Path.GetFileName(snapshotDirectory), StringComparison.Ordinal)) continue;
                result.Add(new SnapshotInfo(manifest.ScopeId, manifest.CreatedAtUtc, snapshotDirectory, DirectorySize(snapshotDirectory)));
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (System.Text.Json.JsonException) { }
        }
        return result;
    }

    private void DeleteSnapshot(SnapshotInfo item)
    {
        try { Directory.Delete(item.DirectoryPath, recursive: true); }
        catch (IOException exception) { _logger.LogWarning(exception, "Could not prune snapshot {SnapshotDirectory}.", item.DirectoryPath); }
        catch (UnauthorizedAccessException exception) { _logger.LogWarning(exception, "Could not prune snapshot {SnapshotDirectory}.", item.DirectoryPath); }
    }

    private static long DirectorySize(string directory) => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Sum(path => new FileInfo(path).Length);
    private sealed record SnapshotInfo(string ScopeId, DateTimeOffset CreatedAtUtc, string DirectoryPath, long Bytes);
}
