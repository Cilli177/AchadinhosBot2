using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class JsonSettingsStore : ISettingsStore
{
    private readonly string _path;
    private readonly string _versionsDir;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly ILogger<JsonSettingsStore> _logger;

    public JsonSettingsStore(ILogger<JsonSettingsStore> logger)
    {
        _logger = logger;
        _path = Path.Combine(AppContext.BaseDirectory, "data", "automation-settings.json");
        _versionsDir = Path.Combine(AppContext.BaseDirectory, "data", "versions");
    }

    public async Task<AutomationSettings> GetAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            if (!File.Exists(_path))
            {
                var defaults = new AutomationSettings();
                await SaveInternalAsync(defaults, cancellationToken);
                return defaults;
            }

            await using var stream = File.OpenRead(_path);
            var settings = await JsonSerializer.DeserializeAsync<AutomationSettings>(stream, cancellationToken: cancellationToken);
            return settings ?? new AutomationSettings();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await SaveVersionSnapshotAsync(cancellationToken);
            await SaveInternalAsync(settings, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task SaveVersionSnapshotAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return;

        Directory.CreateDirectory(_versionsDir);
        var fileName = $"settings-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.json";
        var target = Path.Combine(_versionsDir, fileName);

        await using var source = File.OpenRead(_path);
        await using var dest = File.Create(target);
        await source.CopyToAsync(dest, cancellationToken);
    }

    private async Task SaveInternalAsync(AutomationSettings settings, CancellationToken cancellationToken)
    {
        await using var stream = File.Create(_path);
        await JsonSerializer.SerializeAsync(stream, settings, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
        _logger.LogInformation("Configurações salvas em {Path}", _path);
    }
}
