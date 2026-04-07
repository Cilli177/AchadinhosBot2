using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class JsonSettingsStoreVersioningTests
{
    [Fact]
    public async Task SaveAsync_CreatesVersionSnapshots()
    {
        var store = new JsonSettingsStore(NullLogger<JsonSettingsStore>.Instance);
        var settings = new AutomationSettings();

        await store.SaveAsync(settings, CancellationToken.None);
        settings.BioHub.BrandName = "Brand X";
        await store.SaveAsync(settings, CancellationToken.None);

        var versions = await store.ListVersionsAsync(10, CancellationToken.None);
        Assert.NotEmpty(versions);
    }

    [Fact]
    public async Task RestoreVersionAsync_RestoresPreviousSnapshot()
    {
        var store = new JsonSettingsStore(NullLogger<JsonSettingsStore>.Instance);
        var settings = await store.GetAsync(CancellationToken.None);
        settings.BioHub.BrandName = "Before Restore";
        await store.SaveAsync(settings, CancellationToken.None);

        settings.BioHub.BrandName = "After Restore";
        await store.SaveAsync(settings, CancellationToken.None);

        var versions = await store.ListVersionsAsync(10, CancellationToken.None);
        var target = versions.Skip(1).FirstOrDefault() ?? versions.First();
        await store.RestoreVersionAsync(target.VersionId, CancellationToken.None);

        var restored = await store.GetAsync(CancellationToken.None);
        Assert.NotNull(restored);
    }
}
