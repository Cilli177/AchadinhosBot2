using System.Reflection;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Governance;
using AchadinhosBot.Next.Domain.Offers;
using AchadinhosBot.Next.Infrastructure.Governance;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public class GovernanceSchedulerWorkerTests
{
    [Fact]
    public async Task RunTickAsync_ExecutesObserveDecideActAuditAndPersistsArtifacts()
    {
        var store = new InMemoryGovernanceEventStore();
        var decision = new GovernanceDecision(
            DecisionId: "dec-1",
            DecisionType: "force_outbox_replay",
            Severity: "critical",
            Summary: "outbox backlog",
            SkillName: "auto-healing-orchestrator",
            EntityType: "outbox",
            EntityId: "all",
            MetadataJson: "{}",
            TimestampUtc: DateTimeOffset.UtcNow);

        var worker = new GovernanceSchedulerWorker(
            store,
            new FixedRuleEngine(decision),
            new FixedActionExecutor(success: true),
            new FixedAutoTuningService([
                new TuningChangeRecord("chg-1", "rate_limit", "global", "20", "15", "test", "better throughput", DateTimeOffset.UtcNow)
            ]),
            new FixedOfferAnomalyDetector([
                new OfferAnomaly(
                AnomalyId: "an-1",
                OfferId: "offer-1",
                CatalogTarget: "prod",
                RiskScore: 95,
                Severity: "critical",
                Summary: "invalid link",
                Reasons: ["invalid_url"],
                DetectedAtUtc: DateTimeOffset.UtcNow)
            ]),
            Options.Create(new GovernanceOptions
            {
                Enabled = true,
                SchedulerEnabled = true,
                AutoTuningEnabled = true,
                ShadowMode = false
            }),
            NullLogger<GovernanceSchedulerWorker>.Instance);

        var runTick = typeof(GovernanceSchedulerWorker)
            .GetMethod("RunTickAsync", BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(runTick);
        var task = (Task?)runTick!.Invoke(worker, [CancellationToken.None]);
        Assert.NotNull(task);
        await task!;

        Assert.Contains(store.Events, x => x.Track == GovernanceTracks.Observe && x.EventName == "governance.tick.start");
        Assert.Contains(store.Events, x => x.Track == GovernanceTracks.Decide && x.EventName.Contains("decision.force_outbox_replay", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(store.Events, x => x.Track == GovernanceTracks.Act && x.EventName == "tuning.change.applied");
        Assert.Contains(store.Events, x => x.Track == GovernanceTracks.Audit && x.EventName == "governance.tick.finish");

        Assert.Single(store.Decisions);
        Assert.Single(store.Actions);
        Assert.Single(store.TuningChanges);
        Assert.Contains(store.Incidents, x => x.IncidentType == "offer_anomaly");
        Assert.Contains(store.ResolvedIncidents, x => x == "dec-1");
    }

    [Fact]
    public async Task RunTickAsync_WhenShadowModeEnabled_SimulatesActionWithoutExecution()
    {
        var store = new InMemoryGovernanceEventStore();
        var decision = new GovernanceDecision(
            DecisionId: "dec-shadow",
            DecisionType: "force_outbox_replay",
            Severity: "critical",
            Summary: "outbox backlog",
            SkillName: "auto-healing-orchestrator",
            EntityType: "outbox",
            EntityId: "all",
            MetadataJson: "{}",
            TimestampUtc: DateTimeOffset.UtcNow);
        var actionExecutor = new FixedActionExecutor(success: true);

        var worker = new GovernanceSchedulerWorker(
            store,
            new FixedRuleEngine(decision),
            actionExecutor,
            new FixedAutoTuningService([]),
            new FixedOfferAnomalyDetector([]),
            Options.Create(new GovernanceOptions
            {
                Enabled = true,
                SchedulerEnabled = true,
                AutoTuningEnabled = false,
                ShadowMode = true
            }),
            NullLogger<GovernanceSchedulerWorker>.Instance);

        await InvokeRunTickAsync(worker);

        Assert.Single(store.Decisions);
        Assert.Single(store.Actions);
        Assert.Equal(0, actionExecutor.ExecutionCount);
        Assert.DoesNotContain("dec-shadow", store.ResolvedIncidents);
        Assert.Contains(store.Actions, x => x.Summary.Contains("Shadow mode", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunTickAsync_WhenConcurrentInvocationOccurs_SecondTickIsSkippedByLock()
    {
        var store = new InMemoryGovernanceEventStore();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ruleEngine = new BlockingRuleEngine(gate.Task);

        var worker = new GovernanceSchedulerWorker(
            store,
            ruleEngine,
            new FixedActionExecutor(success: true),
            new FixedAutoTuningService([]),
            new FixedOfferAnomalyDetector([]),
            Options.Create(new GovernanceOptions
            {
                Enabled = true,
                SchedulerEnabled = true,
                AutoTuningEnabled = false,
                ShadowMode = false
            }),
            NullLogger<GovernanceSchedulerWorker>.Instance);

        var first = InvokeRunTickAsync(worker);
        await ruleEngine.Started.Task;
        var second = InvokeRunTickAsync(worker);
        await Task.Delay(50);
        gate.SetResult();
        await Task.WhenAll(first, second);

        Assert.Contains(store.Events, x => x.EventName == "governance.tick.skipped_lock");
    }

    private static async Task InvokeRunTickAsync(GovernanceSchedulerWorker worker)
    {
        var runTick = typeof(GovernanceSchedulerWorker)
            .GetMethod("RunTickAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(runTick);
        var task = (Task?)runTick!.Invoke(worker, [CancellationToken.None]);
        Assert.NotNull(task);
        await task!;
    }

    private sealed class FixedRuleEngine(GovernanceDecision decision) : IGovernanceRuleEngine
    {
        public Task<IReadOnlyList<GovernanceDecision>> EvaluateAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<GovernanceDecision>>([decision]);
    }

    private sealed class BlockingRuleEngine(Task gate) : IGovernanceRuleEngine
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<IReadOnlyList<GovernanceDecision>> EvaluateAsync(CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            await gate;
            return [];
        }
    }

    private sealed class FixedActionExecutor(bool success) : IGovernanceActionExecutor
    {
        public int ExecutionCount { get; private set; }

        public Task<ActionExecution> ExecuteAsync(GovernanceDecision decision, CancellationToken cancellationToken)
        {
            ExecutionCount++;
            return Task.FromResult(new ActionExecution(
                ActionId: "act-1",
                ActionType: decision.DecisionType,
                Severity: decision.Severity,
                Success: success,
                RequiresApproval: false,
                Summary: "executed",
                OutputJson: "{}",
                TimestampUtc: DateTimeOffset.UtcNow));
        }
    }

    private sealed class FixedAutoTuningService(IReadOnlyList<TuningChangeRecord> changes) : IAutoTuningService
    {
        public Task<IReadOnlyList<TuningChangeRecord>> RunAsync(CancellationToken cancellationToken)
            => Task.FromResult(changes);
    }

    private sealed class FixedOfferAnomalyDetector(IReadOnlyList<OfferAnomaly> anomalies) : IOfferAnomalyDetector
    {
        public Task<IReadOnlyList<OfferAnomaly>> DetectAsync(CancellationToken cancellationToken)
            => Task.FromResult(anomalies);
    }

    private sealed class InMemoryGovernanceEventStore : IGovernanceEventStore
    {
        public List<GovernanceEvent> Events { get; } = [];
        public List<GovernanceDecision> Decisions { get; } = [];
        public List<ActionExecution> Actions { get; } = [];
        public List<IncidentState> Incidents { get; } = [];
        public List<TuningChangeRecord> TuningChanges { get; } = [];
        public List<string> ResolvedIncidents { get; } = [];

        public Task AppendEventAsync(GovernanceEvent item, CancellationToken cancellationToken)
        {
            Events.Add(item);
            return Task.CompletedTask;
        }

        public Task AppendDecisionAsync(GovernanceDecision decision, CancellationToken cancellationToken)
        {
            Decisions.Add(decision);
            return Task.CompletedTask;
        }

        public Task AppendActionAsync(ActionExecution action, CancellationToken cancellationToken)
        {
            Actions.Add(action);
            return Task.CompletedTask;
        }

        public Task UpsertIncidentAsync(IncidentState incident, CancellationToken cancellationToken)
        {
            var idx = Incidents.FindIndex(x => x.IncidentId == incident.IncidentId);
            if (idx >= 0)
            {
                Incidents[idx] = incident;
            }
            else
            {
                Incidents.Add(incident);
            }

            return Task.CompletedTask;
        }

        public Task ResolveIncidentAsync(string incidentId, string resolutionSummary, CancellationToken cancellationToken)
        {
            ResolvedIncidents.Add(incidentId);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<GovernanceEvent>> ListEventsAsync(string? track, int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<GovernanceEvent>>(Events.Take(limit).ToArray());

        public Task<IReadOnlyList<GovernanceDecision>> ListDecisionsAsync(int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<GovernanceDecision>>(Decisions.Take(limit).ToArray());

        public Task<IReadOnlyList<ActionExecution>> ListActionsAsync(int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<ActionExecution>>(Actions.Take(limit).ToArray());

        public Task<IReadOnlyList<IncidentState>> ListIncidentsAsync(bool onlyOpen, int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<IncidentState>>(Incidents.Take(limit).ToArray());

        public Task<GovernanceStatusSnapshot> GetStatusSnapshotAsync(CancellationToken cancellationToken)
            => Task.FromResult(new GovernanceStatusSnapshot(DateTimeOffset.UtcNow, 0, 0, 0, 0, 0, 1, null, null));

        public Task AppendTuningChangeAsync(TuningChangeRecord change, CancellationToken cancellationToken)
        {
            TuningChanges.Add(change);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<TuningChangeRecord>> ListTuningChangesAsync(int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<TuningChangeRecord>>(TuningChanges.Take(limit).ToArray());
    }
}
