using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class JsonSettingsStore : ISettingsStore, ISettingsVersionStore
{
    private readonly string _path;
    private readonly string _versionsDir;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly ILogger<JsonSettingsStore> _logger;
    private AutomationSettings? _cachedSettings;
    private DateTimeOffset _cacheExpiresAt = DateTimeOffset.MinValue;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(20);

    public JsonSettingsStore(ILogger<JsonSettingsStore> logger, string? path = null, string? versionsDir = null)
    {
        _logger = logger;
        _path = string.IsNullOrWhiteSpace(path)
            ? Path.Combine(AppContext.BaseDirectory, "data", "automation-settings.json")
            : path;
        _versionsDir = string.IsNullOrWhiteSpace(versionsDir)
            ? Path.Combine(Path.GetDirectoryName(_path) ?? AppContext.BaseDirectory, "versions")
            : versionsDir;
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
            AutomationSettingsSanitizer.NormalizeInPlace(resolved);
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
            AutomationSettingsSanitizer.NormalizeInPlace(settings);

            var current = await ReadCurrentSettingsAsync(cancellationToken);
            LogCriticalDiff(current, settings);

            await SaveVersionSnapshotAsync(cancellationToken);
            await SaveInternalAsync(settings, cancellationToken);
            SetCache(settings);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<SettingsVersionInfo>> ListVersionsAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!Directory.Exists(_versionsDir))
            {
                return Array.Empty<SettingsVersionInfo>();
            }

            return Directory.EnumerateFiles(_versionsDir, "settings-*.json", SearchOption.TopDirectoryOnly)
                .Select(path =>
                {
                    var info = new FileInfo(path);
                    return new SettingsVersionInfo(
                        Path.GetFileName(path),
                        new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero),
                        info.Length);
                })
                .OrderByDescending(x => x.CapturedAtUtc)
                .ThenByDescending(x => x.FileName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<AutomationSettings?> RestoreAsync(string versionFileName, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var normalizedFileName = Path.GetFileName((versionFileName ?? string.Empty).Trim());
            if (string.IsNullOrWhiteSpace(normalizedFileName) ||
                !string.Equals(normalizedFileName, versionFileName?.Trim(), StringComparison.Ordinal))
            {
                return null;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            Directory.CreateDirectory(_versionsDir);

            var sourcePath = Path.Combine(_versionsDir, normalizedFileName);
            if (!File.Exists(sourcePath))
            {
                return null;
            }

            await SaveVersionSnapshotAsync(cancellationToken);

            var tempPath = _path + ".restore.tmp";
            await using (var source = File.OpenRead(sourcePath))
            await using (var dest = File.Create(tempPath))
            {
                await source.CopyToAsync(dest, cancellationToken);
            }

            File.Move(tempPath, _path, true);

            await using var stream = File.OpenRead(_path);
            var settings = await JsonSerializer.DeserializeAsync<AutomationSettings>(stream, cancellationToken: cancellationToken);
            var resolved = settings ?? new AutomationSettings();
            AutomationSettingsSanitizer.NormalizeInPlace(resolved);
            SetCache(resolved);
            _logger.LogInformation("Configuracoes restauradas a partir de {Snapshot}", normalizedFileName);
            return Clone(resolved);
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
        var fileName = $"settings-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.json";
        var target = Path.Combine(_versionsDir, fileName);

        await using var source = File.OpenRead(_path);
        await using var dest = File.Create(target);
        await source.CopyToAsync(dest, cancellationToken);
    }

    private async Task SaveInternalAsync(AutomationSettings settings, CancellationToken cancellationToken)
    {
        await using var stream = File.Create(_path);
        await JsonSerializer.SerializeAsync(stream, settings, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
        _logger.LogInformation("Configuracoes salvas em {Path}", _path);
    }

    private async Task<AutomationSettings?> ReadCurrentSettingsAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return null;
        }

        try
        {
            await using var stream = File.OpenRead(_path);
            var settings = await JsonSerializer.DeserializeAsync<AutomationSettings>(stream, cancellationToken: cancellationToken);
            if (settings is null)
            {
                return null;
            }

            AutomationSettingsSanitizer.NormalizeInPlace(settings);
            return settings;
        }
        catch
        {
            return null;
        }
    }

    private void LogCriticalDiff(AutomationSettings? current, AutomationSettings next)
    {
        if (current is null)
        {
            _logger.LogInformation("Primeiro snapshot de configuracoes criticas: {Summary}", BuildCriticalSummary(next));
            return;
        }

        var diffs = new List<string>();

        AppendDiff(diffs, "BioHub.PublicBaseUrl", current.BioHub?.PublicBaseUrl, next.BioHub?.PublicBaseUrl);
        AppendDiff(diffs, "LinkAutomation.AutoConvertIncomingLinks", current.LinkAutomation?.AutoConvertIncomingLinks, next.LinkAutomation?.AutoConvertIncomingLinks);
        AppendDiff(diffs, "LinkAutomation.AutoSendToDestinationChannel", current.LinkAutomation?.AutoSendToDestinationChannel, next.LinkAutomation?.AutoSendToDestinationChannel);
        AppendDiff(diffs, "LinkAutomation.DestinationChannel", current.LinkAutomation?.DestinationChannel, next.LinkAutomation?.DestinationChannel);
        AppendDiff(diffs, "LinkAutomation.EnableExternalShortener", current.LinkAutomation?.EnableExternalShortener, next.LinkAutomation?.EnableExternalShortener);
        AppendDiff(diffs, "LinkAutomation.ExternalShortenerProvider", current.LinkAutomation?.ExternalShortenerProvider, next.LinkAutomation?.ExternalShortenerProvider);
        AppendDiff(diffs, "LinkAutomation.TrackingLinkValidityDays", current.LinkAutomation?.TrackingLinkValidityDays, next.LinkAutomation?.TrackingLinkValidityDays);
        AppendDiff(diffs, "LinkIntegrity.Enabled", current.LinkIntegrity?.Enabled, next.LinkIntegrity?.Enabled);
        AppendDiff(diffs, "LinkIntegrity.BlockAutomaticFlowOnNonAffiliated", current.LinkIntegrity?.BlockAutomaticFlowOnNonAffiliated, next.LinkIntegrity?.BlockAutomaticFlowOnNonAffiliated);
        AppendDiff(diffs, "LinkIntegrity.BlockAutomaticFlowOnConversionFailure", current.LinkIntegrity?.BlockAutomaticFlowOnConversionFailure, next.LinkIntegrity?.BlockAutomaticFlowOnConversionFailure);
        AppendDiff(diffs, "InstagramPosts.AllowTelegramUserbot", current.InstagramPosts?.AllowTelegramUserbot, next.InstagramPosts?.AllowTelegramUserbot);
        AppendDiff(diffs, "InstagramPosts.AllowTelegramBot", current.InstagramPosts?.AllowTelegramBot, next.InstagramPosts?.AllowTelegramBot);
        AppendDiff(diffs, "InstagramPosts.TelegramAllowPrivate", current.InstagramPosts?.TelegramAllowPrivate, next.InstagramPosts?.TelegramAllowPrivate);
        AppendDiff(diffs, "InstagramPosts.TelegramAllowGroups", current.InstagramPosts?.TelegramAllowGroups, next.InstagramPosts?.TelegramAllowGroups);
        AppendDiff(diffs, "InstagramPosts.TelegramChatIds", current.InstagramPosts?.TelegramChatIds, next.InstagramPosts?.TelegramChatIds);
        AppendDiff(diffs, "TelegramForwarding.Enabled", current.TelegramForwarding?.Enabled, next.TelegramForwarding?.Enabled);
        AppendDiff(diffs, "TelegramForwarding.SourceChatIds", current.TelegramForwarding?.SourceChatIds, next.TelegramForwarding?.SourceChatIds);
        AppendDiff(diffs, "WhatsAppForwarding.Enabled", current.WhatsAppForwarding?.Enabled, next.WhatsAppForwarding?.Enabled);
        AppendDiff(diffs, "WhatsAppForwarding.SourceChatIds", current.WhatsAppForwarding?.SourceChatIds, next.WhatsAppForwarding?.SourceChatIds);
        AppendDiff(diffs, "WhatsAppForwarding.DestinationGroupIds", current.WhatsAppForwarding?.DestinationGroupIds, next.WhatsAppForwarding?.DestinationGroupIds);
        AppendDiff(diffs, "LinkResponder.AllowTelegramUserbot", current.LinkResponder?.AllowTelegramUserbot, next.LinkResponder?.AllowTelegramUserbot);
        AppendDiff(diffs, "LinkResponder.TelegramAllowPrivate", current.LinkResponder?.TelegramAllowPrivate, next.LinkResponder?.TelegramAllowPrivate);
        AppendDiff(diffs, "LinkResponder.TelegramAllowGroups", current.LinkResponder?.TelegramAllowGroups, next.LinkResponder?.TelegramAllowGroups);
        AppendDiff(diffs, "LinkResponder.TelegramChatIds", current.LinkResponder?.TelegramChatIds, next.LinkResponder?.TelegramChatIds);

        if (diffs.Count == 0)
        {
            _logger.LogDebug("Configuracoes salvas sem alteracoes criticas.");
            return;
        }

        _logger.LogWarning("Configuracoes criticas alteradas antes do save: {Diffs}", string.Join(" | ", diffs));
    }

    private static string BuildCriticalSummary(AutomationSettings settings)
    {
        return string.Join(" | ", new[]
        {
            $"BioHub.PublicBaseUrl={settings.BioHub?.PublicBaseUrl ?? string.Empty}",
            $"LinkAutomation.DestinationChannel={settings.LinkAutomation?.DestinationChannel ?? string.Empty}",
            $"LinkAutomation.TrackingLinkValidityDays={settings.LinkAutomation?.TrackingLinkValidityDays ?? 0}",
            $"InstagramPosts.TelegramChatIds={FormatList(settings.InstagramPosts?.TelegramChatIds)}",
            $"WhatsAppForwarding.DestinationGroupIds={FormatList(settings.WhatsAppForwarding?.DestinationGroupIds)}"
        });
    }

    private static void AppendDiff(List<string> diffs, string key, string? current, string? next)
    {
        if (string.Equals(current?.Trim(), next?.Trim(), StringComparison.Ordinal))
        {
            return;
        }

        diffs.Add($"{key}: '{current ?? string.Empty}' -> '{next ?? string.Empty}'");
    }

    private static void AppendDiff(List<string> diffs, string key, bool? current, bool? next)
    {
        if (current == next)
        {
            return;
        }

        diffs.Add($"{key}: '{current?.ToString() ?? string.Empty}' -> '{next?.ToString() ?? string.Empty}'");
    }

    private static void AppendDiff(List<string> diffs, string key, int? current, int? next)
    {
        if (current == next)
        {
            return;
        }

        diffs.Add($"{key}: '{current?.ToString() ?? string.Empty}' -> '{next?.ToString() ?? string.Empty}'");
    }

    private static void AppendDiff<T>(List<string> diffs, string key, IReadOnlyCollection<T>? current, IReadOnlyCollection<T>? next)
    {
        var currentValue = FormatList(current);
        var nextValue = FormatList(next);
        if (string.Equals(currentValue, nextValue, StringComparison.Ordinal))
        {
            return;
        }

        diffs.Add($"{key}: '{currentValue}' -> '{nextValue}'");
    }

    private static string FormatList<T>(IEnumerable<T>? values)
    {
        if (values is null)
        {
            return string.Empty;
        }

        var parts = values
            .Select(x => x?.ToString() ?? string.Empty)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return parts.Length == 0 ? string.Empty : string.Join(",", parts);
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
