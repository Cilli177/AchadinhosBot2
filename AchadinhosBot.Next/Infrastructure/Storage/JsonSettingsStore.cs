using System.Globalization;
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
    private AutomationSettings? _cachedSettings;
    private DateTimeOffset _cacheExpiresAt = DateTimeOffset.MinValue;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(20);

    public JsonSettingsStore(ILogger<JsonSettingsStore> logger)
    {
        _logger = logger;
        _path = Path.Combine(AppContext.BaseDirectory, "data", "automation-settings.json");
        _versionsDir = Path.Combine(AppContext.BaseDirectory, "data", "versions");
    }

    public async Task<AutomationSettings> GetAsync(CancellationToken cancellationToken)
    {
        if (_cachedSettings is not null && DateTimeOffset.UtcNow < _cacheExpiresAt)
        {
            return Clone(_cachedSettings);
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (_cachedSettings is not null && DateTimeOffset.UtcNow < _cacheExpiresAt)
            {
                return Clone(_cachedSettings);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            if (!File.Exists(_path))
            {
                var defaults = new AutomationSettings();
                await SaveInternalAsync(defaults, cancellationToken);
                SetCache(defaults);
                return Clone(defaults);
            }

            await using var stream = File.OpenRead(_path);
            var settings = await JsonSerializer.DeserializeAsync<AutomationSettings>(stream, cancellationToken: cancellationToken);
            var resolved = settings ?? new AutomationSettings();
            SetCache(resolved);
            return Clone(resolved);
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
            SetCache(settings);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<VersionSnapshotInfo>> ListVersionsAsync(int limit, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(_versionsDir);
            var list = Directory.EnumerateFiles(_versionsDir, "settings-*.json", SearchOption.TopDirectoryOnly)
                .Select(path => new FileInfo(path))
                .Select(fi => new VersionSnapshotInfo(
                    Path.GetFileNameWithoutExtension(fi.Name),
                    fi.CreationTimeUtc == DateTime.MinValue ? fi.LastWriteTimeUtc : fi.CreationTimeUtc,
                    fi.Length))
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(Math.Clamp(limit, 1, 500))
                .ToArray();

            return list;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<VersionSnapshotInfo?> GetCurrentVersionAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            var fi = new FileInfo(_path);
            var stamp = fi.LastWriteTimeUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            return new VersionSnapshotInfo($"current-{stamp}", fi.LastWriteTimeUtc, fi.Length);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task RestoreVersionAsync(string versionId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(versionId))
        {
            throw new ArgumentException("versionId é obrigatório.", nameof(versionId));
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(_versionsDir);
            var fileName = versionId.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                ? versionId
                : $"{versionId}.json";
            var sourcePath = Path.Combine(_versionsDir, fileName);
            if (!File.Exists(sourcePath))
            {
                throw new FileNotFoundException($"Snapshot não encontrado: {versionId}", sourcePath);
            }

            await SaveVersionSnapshotAsync(cancellationToken);

            await using var source = File.OpenRead(sourcePath);
            await using var destination = File.Create(_path);
            await source.CopyToAsync(destination, cancellationToken);

            _cachedSettings = null;
            _cacheExpiresAt = DateTimeOffset.MinValue;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task SaveVersionSnapshotAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return;
        }

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

    private void SetCache(AutomationSettings settings)
    {
        _cachedSettings = Clone(settings);
        _cacheExpiresAt = DateTimeOffset.UtcNow.Add(CacheTtl);
    }

    private static AutomationSettings Clone(AutomationSettings settings)
    {
        var json = JsonSerializer.Serialize(settings);
        return JsonSerializer.Deserialize<AutomationSettings>(json) ?? new AutomationSettings();
    }
}
