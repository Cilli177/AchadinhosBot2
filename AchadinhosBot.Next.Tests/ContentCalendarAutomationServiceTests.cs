using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Content;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Content;
using AchadinhosBot.Next.Infrastructure.Instagram;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class ContentCalendarAutomationServiceTests
{
    [Theory]
    [InlineData(false, "draft_created")]
    [InlineData(true, "publish_queued")]
    public async Task ProcessDue_WithSyntheticCompleteItem_DoesNotUseNetworkAndCreatesOneDraft(bool autoPublish, string expectedStatus)
    {
        var item = new ContentCalendarItem
        {
            Id = "synthetic-item",
            ScheduledAt = DateTimeOffset.UtcNow.AddMinutes(-1),
            SourceInput = "Oferta sintética",
            GeneratedCaption = "Legenda sintética",
            MediaUrl = "https://example.invalid/synthetic.jpg",
            AutoPublish = autoPublish,
            Status = "planned"
        };
        var store = new CalendarStore(item);
        var composer = new Composer();
        var publisher = new Publisher();
        var service = new ContentCalendarAutomationService(
            store,
            new Settings(),
            composer,
            new DraftStore(),
            new PublishLogStore(),
            new InstagramLinkMetaService(null!, null!, null!, NullLogger<InstagramLinkMetaService>.Instance),
            publisher,
            NullLogger<ContentCalendarAutomationService>.Instance);

        var result = await service.ProcessDueAsync(CancellationToken.None);

        Assert.Equal(1, result.TotalDue);
        Assert.Equal(1, result.Processed);
        Assert.Equal(1, result.DraftsCreated);
        Assert.Equal(0, composer.Calls);
        Assert.Equal(autoPublish ? 1 : 0, publisher.QueueCalls);
        Assert.Equal(0, publisher.ExecuteCalls);
        Assert.Equal(expectedStatus, item.Status);
        Assert.Null(item.ProcessingExecutionId);
        Assert.Null(item.ProcessingClaimedAt);
    }

    private sealed class Settings : ISettingsStore
    {
        public Task<AutomationSettings> GetAsync(CancellationToken ct) => Task.FromResult(new AutomationSettings { ContentCalendar = new ContentCalendarSettings { MaxAttempts = 3 } });
        public Task SaveAsync(AutomationSettings settings, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class CalendarStore(ContentCalendarItem item) : IContentCalendarStore
    {
        public Task<IReadOnlyList<ContentCalendarItem>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<ContentCalendarItem>>([item]);
        public Task<ContentCalendarItem?> GetAsync(string id, CancellationToken ct) => Task.FromResult<ContentCalendarItem?>(item.Id == id ? item : null);
        public Task SaveAsync(ContentCalendarItem value, CancellationToken ct) => Task.CompletedTask;
        public Task DeleteAsync(string id, CancellationToken ct) => Task.CompletedTask;
        public Task<string> ExportCsvAsync(CancellationToken ct) => Task.FromResult(string.Empty);
        public Task<ContentCalendarItem?> TryClaimDueAsync(string id, string executionId, DateTimeOffset now, int maxAttempts, CancellationToken ct)
        {
            if (item.Id != id || item.Status != "planned") return Task.FromResult<ContentCalendarItem?>(null);
            item.Status = "processing"; item.Attempts++; item.LastAttemptAt = now; item.ProcessingExecutionId = executionId; item.ProcessingClaimedAt = now;
            return Task.FromResult<ContentCalendarItem?>(item);
        }
    }

    private sealed class Composer : IInstagramPostComposer { public int Calls; public Task<string> BuildAsync(string productInput, string? offerContext, InstagramPostSettings settings, CancellationToken ct) { Calls++; return Task.FromResult("unexpected"); } public Task<string> SuggestHashtagsAsync(string productName, InstagramPostSettings settings, CancellationToken ct) => Task.FromResult(string.Empty); }
    private sealed class DraftStore : IInstagramPublishStore { public List<InstagramPublishDraft> Drafts { get; } = []; public Task SaveAsync(InstagramPublishDraft draft, CancellationToken ct) { Drafts.Add(draft); return Task.CompletedTask; } public Task UpdateAsync(InstagramPublishDraft draft, CancellationToken ct) => Task.CompletedTask; public Task<IReadOnlyList<InstagramPublishDraft>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<InstagramPublishDraft>>(Drafts); public Task<InstagramPublishDraft?> GetAsync(string id, CancellationToken ct) => Task.FromResult(Drafts.FirstOrDefault(x => x.Id == id)); public Task ClearAsync(CancellationToken ct) => Task.CompletedTask; }
    private sealed class PublishLogStore : IInstagramPublishLogStore { public Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct) => Task.CompletedTask; public Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct) => Task.FromResult<IReadOnlyList<InstagramPublishLogEntry>>([]); public Task ClearAsync(CancellationToken ct) => Task.CompletedTask; }
    private sealed class Publisher : IInstagramPublishService { public int QueueCalls; public int ExecuteCalls; public Task<InstagramPublishDispatchResult> QueuePublishAsync(string draftId, string? actor, CancellationToken ct) { QueueCalls++; return Task.FromResult(new InstagramPublishDispatchResult(true, "test", "message", false, 202)); } public Task<InstagramPublishExecutionOutcome> ExecutePublishAsync(string draftId, CancellationToken ct) { ExecuteCalls++; return Task.FromResult(new InstagramPublishExecutionOutcome(true, 200, null, null, draftId)); } }
}
