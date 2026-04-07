using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Governance;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public class GovernanceActionExecutorTests
{
    [Fact]
    public async Task ExecuteAsync_AutoRollbackWithoutApproval_ReturnsRequiresApproval()
    {
        var settings = new FakeSettingsStore([new VersionSnapshotInfo("v1", DateTimeOffset.UtcNow, 10)]);
        var canaryStore = new FakeCanaryRuleStore([]);
        var sut = CreateSut(settings, canaryStore, new GovernanceOptions { AllowDestructiveActions = false });

        var result = await sut.ExecuteAsync(Decision("auto_rollback"), CancellationToken.None);

        Assert.False(result.Success);
        Assert.True(result.RequiresApproval);
        Assert.Null(settings.RestoredVersion);
    }

    [Fact]
    public async Task ExecuteAsync_AutoRollbackWithApproval_RestoresLatestSnapshot()
    {
        var settings = new FakeSettingsStore([
            new VersionSnapshotInfo("v-latest", DateTimeOffset.UtcNow, 10),
            new VersionSnapshotInfo("v-older", DateTimeOffset.UtcNow.AddMinutes(-2), 10)
        ]);
        var canaryStore = new FakeCanaryRuleStore([]);
        var sut = CreateSut(settings, canaryStore, new GovernanceOptions { AllowDestructiveActions = true });

        var result = await sut.ExecuteAsync(Decision("auto_rollback"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("v-latest", settings.RestoredVersion);
    }

    [Fact]
    public async Task ExecuteAsync_ForceOutboxReplay_ReplaysAndDeletesMessages()
    {
        var botOutbox = new FakeBotOutbox(2);
        var waOutbox = new FakeWhatsAppOutbox(1);
        var tgOutbox = new FakeTelegramOutbox(1);
        var igOutbox = new FakeInstagramOutbox(1);

        var botPublisher = new FakeBotPublisher();
        var waPublisher = new FakeWhatsAppPublisher();
        var tgPublisher = new FakeTelegramPublisher();
        var igPublisher = new FakeInstagramPublisher();

        var settings = new FakeSettingsStore([]);
        var canaryStore = new FakeCanaryRuleStore([]);

        var sut = new GovernanceActionExecutor(
            botOutbox,
            waOutbox,
            tgOutbox,
            igOutbox,
            botPublisher,
            waPublisher,
            tgPublisher,
            igPublisher,
            settings,
            canaryStore,
            Options.Create(new GovernanceOptions { MaxActionsPerWindow = 10, ActionWindowMinutes = 15 }));

        var result = await sut.ExecuteAsync(Decision("force_outbox_replay"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(2, botPublisher.PublishedCount);
        Assert.Equal(1, waPublisher.PublishedCount);
        Assert.Equal(1, tgPublisher.PublishedCount);
        Assert.Equal(1, igPublisher.PublishedCount);
        Assert.Equal(2, botOutbox.DeletedCount);
        Assert.Equal(1, waOutbox.DeletedCount);
        Assert.Equal(1, tgOutbox.DeletedCount);
        Assert.Equal(1, igOutbox.DeletedCount);
    }

    [Fact]
    public async Task ExecuteAsync_CircuitBreakerBlocksSecondActionInWindow()
    {
        var settings = new FakeSettingsStore([]);
        var canaryStore = new FakeCanaryRuleStore([]);
        var sut = CreateSut(settings, canaryStore, new GovernanceOptions
        {
            MaxActionsPerWindow = 1,
            ActionWindowMinutes = 60,
            AllowDestructiveActions = false
        });

        var first = await sut.ExecuteAsync(Decision("worker_recovery_attempt"), CancellationToken.None);
        var second = await sut.ExecuteAsync(Decision("worker_recovery_attempt"), CancellationToken.None);

        Assert.True(first.Success);
        Assert.False(second.Success);
        Assert.Contains("Circuit breaker", second.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExecuteAsync_CanaryRollback_DisablesAllRules()
    {
        var settings = new FakeSettingsStore([]);
        var canaryStore = new FakeCanaryRuleStore([
            new CanaryRule("r1", true, "global", null, null, null, 25),
            new CanaryRule("r2", true, "whatsapp_send", "g1", "i1", "whatsapp", 50)
        ]);
        var sut = CreateSut(settings, canaryStore, new GovernanceOptions());

        var result = await sut.ExecuteAsync(Decision("canary_rollback"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.All(canaryStore.CurrentRules, x =>
        {
            Assert.False(x.Enabled);
            Assert.Equal(0, x.CanaryPercent);
        });
    }

    private static GovernanceActionExecutor CreateSut(FakeSettingsStore settings, FakeCanaryRuleStore canaryStore, GovernanceOptions options)
        => new(
            new FakeBotOutbox(0),
            new FakeWhatsAppOutbox(0),
            new FakeTelegramOutbox(0),
            new FakeInstagramOutbox(0),
            new FakeBotPublisher(),
            new FakeWhatsAppPublisher(),
            new FakeTelegramPublisher(),
            new FakeInstagramPublisher(),
            settings,
            canaryStore,
            Options.Create(options));

    private static GovernanceDecision Decision(string type)
        => new(Guid.NewGuid().ToString("N"), type, "critical", "test", "skill", "runtime", "global", "{}", DateTimeOffset.UtcNow);

    private sealed class FakeSettingsStore(IReadOnlyList<VersionSnapshotInfo> versions) : ISettingsStore
    {
        public string? RestoredVersion { get; private set; }

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(new AutomationSettings());
        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<VersionSnapshotInfo>> ListVersionsAsync(int limit, CancellationToken cancellationToken) => Task.FromResult(versions);
        public Task<VersionSnapshotInfo?> GetCurrentVersionAsync(CancellationToken cancellationToken) => Task.FromResult(versions.FirstOrDefault());
        public Task RestoreVersionAsync(string versionId, CancellationToken cancellationToken)
        {
            RestoredVersion = versionId;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeCanaryRuleStore(IReadOnlyList<CanaryRule> seed) : ICanaryRuleStore
    {
        private List<CanaryRule> _rules = [.. seed];
        public IReadOnlyList<CanaryRule> CurrentRules => _rules;
        public Task<IReadOnlyList<CanaryRule>> ListAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<CanaryRule>>(_rules);
        public Task SaveAsync(IReadOnlyList<CanaryRule> rules, CancellationToken cancellationToken)
        {
            _rules = [.. rules];
            return Task.CompletedTask;
        }
    }

    private sealed class FakeBotOutbox(int count) : IBotConversorOutboxStore
    {
        private readonly List<ProcessBotConversorWebhookCommand> _items = Enumerable.Range(0, count).Select(i => new ProcessBotConversorWebhookCommand { MessageId = $"bot-{i}" }).ToList();
        public int DeletedCount { get; private set; }
        public Task SaveAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<ProcessBotConversorWebhookCommand>> ListPendingAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ProcessBotConversorWebhookCommand>>(_items);
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken)
        {
            DeletedCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeWhatsAppOutbox(int count) : IWhatsAppOutboundOutboxStore
    {
        private readonly List<SendWhatsAppMessageCommand> _items = Enumerable.Range(0, count).Select(i => new SendWhatsAppMessageCommand { MessageId = $"wa-{i}", To = "5511999999999" }).ToList();
        public int DeletedCount { get; private set; }
        public Task SaveAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<SendWhatsAppMessageCommand>> ListPendingAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<SendWhatsAppMessageCommand>>(_items);
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken)
        {
            DeletedCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTelegramOutbox(int count) : ITelegramOutboundOutboxStore
    {
        private readonly List<SendTelegramMessageCommand> _items = Enumerable.Range(0, count).Select(i => new SendTelegramMessageCommand { MessageId = $"tg-{i}", ChatId = 1 }).ToList();
        public int DeletedCount { get; private set; }
        public Task SaveAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<SendTelegramMessageCommand>> ListPendingAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<SendTelegramMessageCommand>>(_items);
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken)
        {
            DeletedCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeInstagramOutbox(int count) : IInstagramOutboundOutboxStore
    {
        private readonly List<InstagramOutboundEnvelope> _items = Enumerable.Range(0, count).Select(i => new InstagramOutboundEnvelope
        {
            MessageId = $"ig-{i}",
            MessageType = "publish",
            PayloadJson = JsonSerializer.Serialize(new PublishInstagramPostCommand { DraftId = "d1", MessageId = $"pub-{i}" })
        }).ToList();
        public int DeletedCount { get; private set; }
        public Task SaveAsync(InstagramOutboundEnvelope envelope, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<InstagramOutboundEnvelope>> ListPendingAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<InstagramOutboundEnvelope>>(_items);
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken)
        {
            DeletedCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeBotPublisher : IBotConversorQueuePublisher
    {
        public int PublishedCount { get; private set; }
        public Task PublishAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken)
        {
            PublishedCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeWhatsAppPublisher : IWhatsAppOutboundPublisher
    {
        public int PublishedCount { get; private set; }
        public Task PublishAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken)
        {
            PublishedCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTelegramPublisher : ITelegramOutboundPublisher
    {
        public int PublishedCount { get; private set; }
        public Task PublishAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken)
        {
            PublishedCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeInstagramPublisher : IInstagramOutboundPublisher
    {
        public int PublishedCount { get; private set; }
        public Task PublishAsync(PublishInstagramPostCommand command, CancellationToken cancellationToken)
        {
            PublishedCount++;
            return Task.CompletedTask;
        }

        public Task PublishAsync(ReplyInstagramCommentCommand command, CancellationToken cancellationToken)
        {
            PublishedCount++;
            return Task.CompletedTask;
        }

        public Task PublishAsync(SendInstagramDirectMessageCommand command, CancellationToken cancellationToken)
        {
            PublishedCount++;
            return Task.CompletedTask;
        }
    }
}
