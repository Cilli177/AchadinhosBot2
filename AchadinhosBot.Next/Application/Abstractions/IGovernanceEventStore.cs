using AchadinhosBot.Next.Domain.Governance;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IGovernanceEventStore
{
    Task AppendEventAsync(GovernanceEvent item, CancellationToken cancellationToken);
    Task AppendDecisionAsync(GovernanceDecision decision, CancellationToken cancellationToken);
    Task AppendActionAsync(ActionExecution action, CancellationToken cancellationToken);
    Task UpsertIncidentAsync(IncidentState incident, CancellationToken cancellationToken);
    Task ResolveIncidentAsync(string incidentId, string resolutionSummary, CancellationToken cancellationToken);
    Task<IReadOnlyList<GovernanceEvent>> ListEventsAsync(string? track, int limit, CancellationToken cancellationToken);
    Task<IReadOnlyList<GovernanceDecision>> ListDecisionsAsync(int limit, CancellationToken cancellationToken);
    Task<IReadOnlyList<ActionExecution>> ListActionsAsync(int limit, CancellationToken cancellationToken);
    Task<IReadOnlyList<IncidentState>> ListIncidentsAsync(bool onlyOpen, int limit, CancellationToken cancellationToken);
    Task<GovernanceStatusSnapshot> GetStatusSnapshotAsync(CancellationToken cancellationToken);
    Task AppendTuningChangeAsync(TuningChangeRecord change, CancellationToken cancellationToken);
    Task<IReadOnlyList<TuningChangeRecord>> ListTuningChangesAsync(int limit, CancellationToken cancellationToken);
}

public interface IGovernanceRuleEngine
{
    Task<IReadOnlyList<GovernanceDecision>> EvaluateAsync(CancellationToken cancellationToken);
}

public interface IGovernanceActionExecutor
{
    Task<ActionExecution> ExecuteAsync(GovernanceDecision decision, CancellationToken cancellationToken);
}

public interface IAutoTuningService
{
    Task<IReadOnlyList<TuningChangeRecord>> RunAsync(CancellationToken cancellationToken);
}

public interface ITrafficCanaryResolver
{
    Task<CanaryResolution> ResolveAsync(CanaryRoutingContext context, CancellationToken cancellationToken);
}

public interface ICanaryRuleStore
{
    Task<IReadOnlyList<CanaryRule>> ListAsync(CancellationToken cancellationToken);
    Task SaveAsync(IReadOnlyList<CanaryRule> rules, CancellationToken cancellationToken);
}
