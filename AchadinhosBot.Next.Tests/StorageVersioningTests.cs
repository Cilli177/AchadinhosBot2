using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class StorageVersioningTests
{
    private readonly string _tempDir;
    private readonly string _settingsPath;
    private readonly string _settingsVersionsDir;
    private readonly string _linkTrackingPath;

    public StorageVersioningTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "achadinhos-storage-versioning-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _settingsPath = Path.Combine(_tempDir, "automation-settings.json");
        _settingsVersionsDir = Path.Combine(_tempDir, "versions");
        _linkTrackingPath = Path.Combine(_tempDir, "link-tracking.json");
    }

    [Fact]
    public async Task JsonSettingsStore_ShouldRestorePreviousSnapshot()
    {
        var store = new JsonSettingsStore(
            NullLogger<JsonSettingsStore>.Instance,
            _settingsPath,
            _settingsVersionsDir);

        var first = await store.GetAsync(CancellationToken.None);
        first.BioHub.PublicBaseUrl = "https://reidasofertas.ia.br";
        first.LinkAutomation.DestinationChannel = "@canal1";
        await store.SaveAsync(first, CancellationToken.None);

        var second = await store.GetAsync(CancellationToken.None);
        second.BioHub.PublicBaseUrl = "https://example.com";
        second.LinkAutomation.DestinationChannel = "@canal2";
        await store.SaveAsync(second, CancellationToken.None);

        var versions = await store.ListVersionsAsync(CancellationToken.None);
        Assert.NotEmpty(versions);

        var restored = await store.RestoreAsync(versions[0].FileName, CancellationToken.None);
        Assert.NotNull(restored);
        Assert.Equal("https://reidasofertas.ia.br", restored!.BioHub.PublicBaseUrl);
        Assert.Equal("@canal1", restored.LinkAutomation.DestinationChannel);

        var current = await store.GetAsync(CancellationToken.None);
        Assert.Equal("https://reidasofertas.ia.br", current.BioHub.PublicBaseUrl);
        Assert.Equal("@canal1", current.LinkAutomation.DestinationChannel);
    }

    [Fact]
    public async Task LinkTrackingStore_ShouldCreateVersionBackups()
    {
        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _linkTrackingPath);

        await store.CreateAsync("https://www.amazon.com.br/dp/B08N5M7S6K", CancellationToken.None);
        await store.CreateAsync("https://s.shopee.com.br/AUpvSsCTgY", CancellationToken.None);

        var versionsDir = Path.Combine(_tempDir, "versions");
        var backups = Directory.Exists(versionsDir)
            ? Directory.GetFiles(versionsDir, "link-tracking.*.json.bak", SearchOption.TopDirectoryOnly)
            : Array.Empty<string>();

        Assert.NotEmpty(backups);
    }

}
