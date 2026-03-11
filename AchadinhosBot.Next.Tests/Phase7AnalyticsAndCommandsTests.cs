using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Infrastructure.Telegram;

namespace AchadinhosBot.Next.Tests;

public sealed class Phase7AnalyticsAndCommandsTests
{
    [Fact]
    public void InstagramAutoPilotCommandParser_ParsesStoryCommand_WithDryRun()
    {
        var parsed = InstagramAutoPilotCommandParser.ParseManualCommand(
            "story",
            new[] { "dry", "https://example.com/oferta" },
            12345);

        Assert.NotNull(parsed.Request);
        Assert.Null(parsed.ErrorMessage);
        Assert.Equal("story", parsed.Request!.PostType);
        Assert.Equal("https://example.com/oferta", parsed.Request.ManualUrl);
        Assert.True(parsed.Request.DryRun);
        Assert.False(parsed.Request.SendForApproval ?? true);
    }

    [Fact]
    public void InstagramAutoPilotCommandParser_ReturnsError_WhenLinkIsMissing()
    {
        var parsed = InstagramAutoPilotCommandParser.ParseManualCommand("post", Array.Empty<string>(), 12345);

        Assert.Null(parsed.Request);
        Assert.Contains("/post https://...", parsed.ErrorMessage);
    }

    [Fact]
    public async Task OperationalAnalyticsService_AggregatesProviderAndPublishMetrics()
    {
        var now = DateTimeOffset.UtcNow;
        var service = new OperationalAnalyticsService(
            new StubConversionLogStore(
                new ConversionLogEntry { Timestamp = now.AddHours(-1), Source = "telegram", Store = "Amazon", Success = true, IsAffiliated = true, ElapsedMs = 1200 },
                new ConversionLogEntry { Timestamp = now.AddHours(-2), Source = "whatsapp", Store = "Shopee", Success = false, IsAffiliated = false, ElapsedMs = 800 }),
            new StubClickLogStore(
                new ClickLogEntry { Timestamp = now.AddMinutes(-30), Source = "instagram", TrackingId = "trk-1", Campaign = "vip" },
                new ClickLogEntry { Timestamp = now.AddMinutes(-20), Source = "instagram", TrackingId = "trk-2", Campaign = "vip" }),
            new StubInstagramAiLogStore(
                new InstagramAiLogEntry { Timestamp = now.AddMinutes(-10), Provider = "openai", Success = true, DurationMs = 900, QualityScore = 88 },
                new InstagramAiLogEntry { Timestamp = now.AddMinutes(-5), Provider = "gemini", Success = false, DurationMs = 1500, QualityScore = 40 }),
            new StubInstagramPublishLogStore(
                new InstagramPublishLogEntry { Timestamp = now.AddMinutes(-15), Action = "publish_queued", Success = true },
                new InstagramPublishLogEntry { Timestamp = now.AddMinutes(-14), Action = "publish", Success = true },
                new InstagramPublishLogEntry { Timestamp = now.AddMinutes(-13), Action = "catalog_sync_after_publish", Success = true }),
            new StubInstagramPublishStore(
                new InstagramPublishDraft { Id = "draft-1", CreatedAt = now.AddMinutes(-16), Status = "published", SendToCatalog = true, CatalogTarget = CatalogTargets.Prod },
                new InstagramPublishDraft { Id = "draft-2", CreatedAt = now.AddMinutes(-12), Status = "scheduled" }),
            new StubCatalogOfferStore(
                new CatalogOfferItem { DraftId = "draft-1", ItemNumber = 1, Keyword = "ITEM1", ProductName = "Produto", Active = true, CatalogTarget = CatalogTargets.Prod }));

        var summary = await service.GetSummaryAsync(24, CancellationToken.None);

        Assert.Equal(2, summary.Conversions.Total);
        Assert.Equal(1, summary.Conversions.Success);
        Assert.Equal(2, summary.Clicks.Total);
        Assert.Equal(1, summary.InstagramPublish.Published);
        Assert.Equal(1, summary.InstagramPublish.CatalogSyncs);
        Assert.Equal(1, summary.InstagramPublish.ScheduledPending);
        Assert.Equal(2, summary.InstagramAi.Total);
        Assert.Equal(2, summary.InstagramAi.Providers.Count);
        Assert.Equal(1, summary.Catalog.ActiveItems);
        Assert.Equal(1, summary.Catalog.SyncEligibleDrafts);
    }

    private sealed class StubConversionLogStore(params ConversionLogEntry[] entries) : IConversionLogStore
    {
        private readonly IReadOnlyList<ConversionLogEntry> _entries = entries;
        public Task AppendAsync(ConversionLogEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<ConversionLogEntry>> QueryAsync(ConversionLogQuery query, CancellationToken cancellationToken)
            => Task.FromResult(_entries);
        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubClickLogStore(params ClickLogEntry[] entries) : IClickLogStore
    {
        private readonly IReadOnlyList<ClickLogEntry> _entries = entries;
        public Task AppendAsync(ClickLogEntry entry, string? category, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<ClickLogEntry>> QueryAsync(string? category, string? search, int limit, CancellationToken cancellationToken)
            => Task.FromResult(_entries);
        public Task ClearAsync(string? category, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubInstagramAiLogStore(params InstagramAiLogEntry[] entries) : IInstagramAiLogStore
    {
        private readonly IReadOnlyList<InstagramAiLogEntry> _entries = entries;
        public Task AppendAsync(InstagramAiLogEntry entry, CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<InstagramAiLogEntry>> ListAsync(int take, CancellationToken ct) => Task.FromResult(_entries);
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StubInstagramPublishLogStore(params InstagramPublishLogEntry[] entries) : IInstagramPublishLogStore
    {
        private readonly IReadOnlyList<InstagramPublishLogEntry> _entries = entries;
        public Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct) => Task.FromResult(_entries);
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StubInstagramPublishStore(params InstagramPublishDraft[] drafts) : IInstagramPublishStore
    {
        private readonly IReadOnlyList<InstagramPublishDraft> _drafts = drafts;
        public Task<IReadOnlyList<InstagramPublishDraft>> ListAsync(CancellationToken ct) => Task.FromResult(_drafts);
        public Task<InstagramPublishDraft?> GetAsync(string id, CancellationToken ct) => Task.FromResult(_drafts.FirstOrDefault(x => x.Id == id));
        public Task SaveAsync(InstagramPublishDraft draft, CancellationToken ct) => Task.CompletedTask;
        public Task UpdateAsync(InstagramPublishDraft draft, CancellationToken ct) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StubCatalogOfferStore(params CatalogOfferItem[] items) : ICatalogOfferStore
    {
        private readonly IReadOnlyList<CatalogOfferItem> _items = items;
        public Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
            => Task.FromResult(new CatalogSyncResult());

        public Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult(_items);

        public Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult(_items.FirstOrDefault());

        public Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<IReadOnlyDictionary<string, CatalogOfferItem>>(_items.ToDictionary(x => x.DraftId, x => x));
    }
}
