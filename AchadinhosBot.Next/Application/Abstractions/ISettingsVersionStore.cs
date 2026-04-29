using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Abstractions;

public sealed record SettingsVersionInfo(string FileName, DateTimeOffset CapturedAtUtc, long SizeBytes);

public interface ISettingsVersionStore
{
    Task<IReadOnlyList<SettingsVersionInfo>> ListVersionsAsync(CancellationToken cancellationToken);
    Task<AutomationSettings?> RestoreAsync(string versionFileName, CancellationToken cancellationToken);
}
