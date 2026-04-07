using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ISettingsStore
{
    Task<AutomationSettings> GetAsync(CancellationToken cancellationToken);
    Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken);
    Task<IReadOnlyList<VersionSnapshotInfo>> ListVersionsAsync(int limit, CancellationToken cancellationToken);
    Task<VersionSnapshotInfo?> GetCurrentVersionAsync(CancellationToken cancellationToken);
    Task RestoreVersionAsync(string versionId, CancellationToken cancellationToken);
}

public sealed record VersionSnapshotInfo(
    string VersionId,
    DateTimeOffset CreatedAtUtc,
    long SizeBytes);
