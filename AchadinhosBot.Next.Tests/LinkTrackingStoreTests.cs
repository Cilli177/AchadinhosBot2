using AchadinhosBot.Next.Infrastructure.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class LinkTrackingStoreTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _storePath;

    public LinkTrackingStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "achadinhos-linktracking-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _storePath = Path.Combine(_tempDir, "link-tracking.json");
    }

    [Fact]
    public async Task GetOrCreateAsync_ShouldGenerateStorePrefixAndKeepSequence()
    {
        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _storePath);
        var ct = CancellationToken.None;

        var amazon1 = await store.GetOrCreateAsync("https://www.amazon.com.br/dp/B0TESTE1", ct);
        var amazon2 = await store.GetOrCreateAsync("https://www.amazon.com.br/dp/B0TESTE2", ct);
        var mercado1 = await store.GetOrCreateAsync("https://meli.la/2mrFTYt", ct);

        Assert.Equal("AM-000001", amazon1.Id);
        Assert.Equal("AM-000002", amazon2.Id);
        Assert.Equal("ML-000001", mercado1.Id);
    }

    [Fact]
    public async Task CreateAsync_ShouldAlwaysGenerateFreshSlugForSameTargetUrl()
    {
        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _storePath);
        var ct = CancellationToken.None;

        var first = await store.CreateAsync("https://tinyurl.com/34cak37t", ct);
        var second = await store.CreateAsync("https://tinyurl.com/34cak37t", ct);

        Assert.Equal("LK-000001", first.Id);
        Assert.Equal("LK-000002", second.Id);
    }

    [Fact]
    public async Task GetOrCreateAsync_ShouldRenewExpiredTargetUrlWithNewSlug()
    {
        var expiredAt = DateTimeOffset.UtcNow.AddDays(-6);
        var payload = $$"""
        {
          "AM-000010": {
            "Id": "AM-000010",
            "Slug": "AM-000010",
            "TargetUrl": "https://www.amazon.com.br/dp/B0RENEW01",
            "Clicks": 8,
            "CreatedAt": "{{expiredAt:O}}",
            "ExpiresAtUtc": "{{expiredAt:O}}"
          }
        }
        """;
        await File.WriteAllTextAsync(_storePath, payload);

        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _storePath);
        var renewed = await store.GetOrCreateAsync("https://www.amazon.com.br/dp/B0RENEW01", CancellationToken.None);

        Assert.Equal("AM-000011", renewed.Id);
        Assert.Equal("AM-000011", renewed.Slug);

        var expired = await store.GetLinkAsync("AM-000010", CancellationToken.None);
        Assert.Null(expired);
    }

    [Fact]
    public async Task GetOrCreateAsync_ShouldRenewLegacyLowSequenceIdsEvenWhenActive()
    {
        var now = DateTimeOffset.UtcNow;
        var legacyUrl = "https://www.amazon.com.br/dp/B0LOWSEQ01";
        var payload = $$"""
        {
          "AM-000010": {
            "Id": "AM-000010",
            "Slug": "AM-000010",
            "TargetUrl": "{{legacyUrl}}",
            "Clicks": 3,
            "CreatedAt": "{{now:O}}",
            "ExpiresAtUtc": "{{now.AddDays(10):O}}"
          }
        }
        """;
        await File.WriteAllTextAsync(_storePath, payload);

        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _storePath);
        var renewed = await store.GetOrCreateAsync(legacyUrl, CancellationToken.None);

        Assert.Equal("AM-000011", renewed.Id);
        Assert.Equal("AM-000011", renewed.Slug);
    }

    [Fact]
    public async Task GetOrCreateAsync_ShouldReplaceDeprecatedPrefixIds()
    {
        var now = DateTimeOffset.UtcNow;
        var legacyUrl = "https://www.amazon.com.br/dp/B0LEGACY01";
        var payload = $$"""
        {
          "AMZ-000777": {
            "Id": "AMZ-000777",
            "Slug": "AMZ-000777",
            "TargetUrl": "{{legacyUrl}}",
            "Clicks": 3,
            "CreatedAt": "{{now:O}}"
          },
          "SHP-000123": {
            "Id": "SHP-000123",
            "Slug": "SHP-000123",
            "TargetUrl": "https://shopee.com.br/legacy",
            "Clicks": 1,
            "CreatedAt": "{{now:O}}"
          }
        }
        """;
        await File.WriteAllTextAsync(_storePath, payload);

        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _storePath);
        var migrated = await store.GetOrCreateAsync(legacyUrl, CancellationToken.None);

        Assert.Equal("AM-000001", migrated.Id);
        Assert.Equal("AM-000001", migrated.Slug);
    }

    [Fact]
    public async Task GetLinkAsync_ShouldReloadWhenBackingFileChanges()
    {
        var initial = $$"""
        {
          "ML-000010": {
            "Id": "ML-000010",
            "Slug": "ML-000010",
            "TargetUrl": "https://www.mercadolivre.com.br/p/MLB000010",
            "Clicks": 0,
            "CreatedAt": "{{DateTimeOffset.UtcNow:O}}"
          }
        }
        """;
        await File.WriteAllTextAsync(_storePath, initial);

        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _storePath);
        var first = await store.GetLinkAsync("ML-000010", CancellationToken.None);
        Assert.NotNull(first);

        var updated = $$"""
        {
          "ML-000010": {
            "Id": "ML-000010",
            "Slug": "ML-000010",
            "TargetUrl": "https://www.mercadolivre.com.br/p/MLB000010",
            "Clicks": 0,
            "CreatedAt": "{{DateTimeOffset.UtcNow:O}}"
          },
          "ML-001664": {
            "Id": "ML-001664",
            "Slug": "ML-001664",
            "TargetUrl": "https://www.mercadolivre.com.br/p/MLB25929487?matt_tool=98187057&matt_word=land177",
            "Clicks": 0,
            "CreatedAt": "{{DateTimeOffset.UtcNow:O}}"
          }
        }
        """;
        await File.WriteAllTextAsync(_storePath, updated);

        var reloaded = await store.GetLinkAsync("ML-001664", CancellationToken.None);

        Assert.NotNull(reloaded);
        Assert.Equal("https://www.mercadolivre.com.br/p/MLB25929487?matt_tool=98187057&matt_word=land177", reloaded!.TargetUrl);
    }

    [Fact]
    public async Task GetLinkAsync_ShouldRecoverFromLatestBackupWhenPrimaryFileIsMissing()
    {
        var versionsDir = Path.Combine(_tempDir, "versions");
        Directory.CreateDirectory(versionsDir);

        var backup = $$"""
        {
          "ML-001664": {
            "Id": "ML-001664",
            "Slug": "ML-001664",
            "TargetUrl": "https://www.mercadolivre.com.br/p/MLB25929487?matt_tool=98187057&matt_word=land177",
            "Clicks": 0,
            "CreatedAt": "{{DateTimeOffset.UtcNow:O}}"
          }
        }
        """;

        var backupPath = Path.Combine(versionsDir, $"link-tracking.{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.json.bak");
        await File.WriteAllTextAsync(backupPath, backup);

        var store = new LinkTrackingStore(NullLogger<LinkTrackingStore>.Instance, _storePath);

        var recovered = await store.GetLinkAsync("ML-001664", CancellationToken.None);

        Assert.NotNull(recovered);
        Assert.Equal("https://www.mercadolivre.com.br/p/MLB25929487?matt_tool=98187057&matt_word=land177", recovered!.TargetUrl);
        Assert.True(File.Exists(_storePath));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
