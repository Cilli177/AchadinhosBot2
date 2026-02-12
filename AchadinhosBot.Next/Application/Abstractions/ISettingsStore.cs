using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ISettingsStore
{
    Task<AutomationSettings> GetAsync(CancellationToken cancellationToken);
    Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken);
}
