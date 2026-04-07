using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Governance;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public class GovernanceRuleEngineTests
{
    [Fact]
    public async Task EvaluateAsync_WhenOutboxBacklogIsCritical_ReturnsReplayDecision()
    {
        var eventStore = new FakeGovernanceEventStore
        {
            Snapshot = new GovernanceStatusSnapshot(DateTimeOffset.UtcNow, 0, 0, 0, 0, 0, 1, null, null)
        };

        var sut = new GovernanceRuleEngine(
            eventStore,
            new FixedBotOutboxStore(10),
            new FixedWhatsAppOutboxStore(8),
            new FixedTelegramOutboxStore(7),
            new FixedInstagramOutboxStore(1),
            new FixedCanaryRuleStore([]),
            new WorkerActivityTracker(),
            Options.Create(new GovernanceOptions
            {
                CriticalOutboxBacklogThreshold = 20,
                AutoRollbackEnabled = false
            }));

        var decisions = await sut.EvaluateAsync(CancellationToken.None);

        var replay = Assert.Single(decisions, x => x.DecisionType == "force_outbox_replay");
        Assert.Equal("critical", replay.Severity);
    }

    [Fact]
    public async Task EvaluateAsync_WhenCriticalIncidentsAreHigh_ReturnsAutoRollbackDecision()
    {
        var eventStore = new FakeGovernanceEventStore
        {
            Snapshot = new GovernanceStatusSnapshot(DateTimeOffset.UtcNow, 4, 3, 10, 9, 6, 0.2, null, null)
        };

        var sut = new GovernanceRuleEngine(
            eventStore,
            new FixedBotOutboxStore(0),
            new FixedWhatsAppOutboxStore(0),
            new FixedTelegramOutboxStore(0),
            new FixedInstagramOutboxStore(0),
            new FixedCanaryRuleStore([]),
            new WorkerActivityTracker(),
            Options.Create(new GovernanceOptions
            {
                CriticalOutboxBacklogThreshold = 20,
                AutoRollbackEnabled = true
            }));

        var decisions = await sut.EvaluateAsync(CancellationToken.None);

        var rollback = Assert.Single(decisions, x => x.DecisionType == "auto_rollback");
        Assert.Equal("critical", rollback.Severity);
    }

    [Fact]
    public async Task EvaluateAsync_WhenCanaryIsEnabledAndFailuresGrow_ReturnsCanaryRollbackDecision()
    {
        var eventStore = new FakeGovernanceEventStore
        {
            Snapshot = new GovernanceStatusSnapshot(DateTimeOffset.UtcNow, 2, 2, 10, 9, 3, 0.2, null, null)
        };

        var sut = new GovernanceRuleEngine(
            eventStore,
            new FixedBotOutboxStore(0),
            new FixedWhatsAppOutboxStore(0),
            new FixedTelegramOutboxStore(0),
            new FixedInstagramOutboxStore(0),
            new FixedCanaryRuleStore([new CanaryRule("r1", true, "global", null, null, null, 30)]),
            new WorkerActivityTracker(),
            Options.Create(new GovernanceOptions
            {
                CriticalOutboxBacklogThreshold = 20,
                AutoRollbackEnabled = true
            }));

        var decisions = await sut.EvaluateAsync(CancellationToken.None);

        var canaryRollback = Assert.Single(decisions, x => x.DecisionType == "canary_rollback");
        Assert.Equal("critical", canaryRollback.Severity);
    }

    private sealed class FixedBotOutboxStore(int count) : IBotConversorOutboxStore
    {
        public Task SaveAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<ProcessBotConversorWebhookCommand>> ListPendingAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<ProcessBotConversorWebhookCommand>>(Enumerable.Range(0, count).Select(_ => new ProcessBotConversorWebhookCommand()).ToArray());
    }

    private sealed class FixedWhatsAppOutboxStore(int count) : IWhatsAppOutboundOutboxStore
    {
        public Task SaveAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<SendWhatsAppMessageCommand>> ListPendingAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<SendWhatsAppMessageCommand>>(Enumerable.Range(0, count).Select(_ => new SendWhatsAppMessageCommand()).ToArray());
    }

    private sealed class FixedTelegramOutboxStore(int count) : ITelegramOutboundOutboxStore
    {
        public Task SaveAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<SendTelegramMessageCommand>> ListPendingAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<SendTelegramMessageCommand>>(Enumerable.Range(0, count).Select(_ => new SendTelegramMessageCommand()).ToArray());
    }

    private sealed class FixedInstagramOutboxStore(int count) : IInstagramOutboundOutboxStore
    {
        public Task SaveAsync(InstagramOutboundEnvelope envelope, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<InstagramOutboundEnvelope>> ListPendingAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<InstagramOutboundEnvelope>>(Enumerable.Range(0, count).Select(_ => new InstagramOutboundEnvelope()).ToArray());
    }

    private sealed class FakeGovernanceEventStore : IGovernanceEventStore
    {
        public GovernanceStatusSnapshot Snapshot { get; set; } = new(DateTimeOffset.UtcNow, 0, 0, 0, 0, 0, 0, null, null);

        public Task AppendActionAsync(ActionExecution action, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task AppendDecisionAsync(GovernanceDecision decision, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task AppendEventAsync(GovernanceEvent item, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task AppendTuningChangeAsync(TuningChangeRecord change, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<GovernanceStatusSnapshot> GetStatusSnapshotAsync(CancellationToken cancellationToken) => Task.FromResult(Snapshot);
        public Task<IReadOnlyList<ActionExecution>> ListActionsAsync(int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ActionExecution>>([]);
        public Task<IReadOnlyList<GovernanceDecision>> ListDecisionsAsync(int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<GovernanceDecision>>([]);
        public Task<IReadOnlyList<GovernanceEvent>> ListEventsAsync(string? track, int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<GovernanceEvent>>([]);
        public Task<IReadOnlyList<IncidentState>> ListIncidentsAsync(bool onlyOpen, int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<IncidentState>>([]);
        public Task<IReadOnlyList<TuningChangeRecord>> ListTuningChangesAsync(int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<TuningChangeRecord>>([]);
        public Task ResolveIncidentAsync(string incidentId, string resolutionSummary, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task UpsertIncidentAsync(IncidentState incident, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FixedCanaryRuleStore(IReadOnlyList<CanaryRule> rules) : ICanaryRuleStore
    {
        public Task<IReadOnlyList<CanaryRule>> ListAsync(CancellationToken cancellationToken) => Task.FromResult(rules);
        public Task SaveAsync(IReadOnlyList<CanaryRule> rules, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
