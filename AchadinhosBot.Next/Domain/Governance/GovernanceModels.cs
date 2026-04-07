namespace AchadinhosBot.Next.Domain.Governance;

public static class GovernanceTracks
{
    public const string Observe = "observe";
    public const string Decide = "decide";
    public const string Act = "act";
    public const string Audit = "audit";
}

public sealed record GovernanceEvent(
    string Track,
    string EventName,
    string Severity,
    string Result,
    string? SkillName,
    string? EntityType,
    string? EntityId,
    string? CorrelationId,
    string? TraceId,
    long? DurationMs,
    DateTimeOffset TimestampUtc,
    string PayloadJson);

public sealed record RuleEvaluation(
    string RuleId,
    string Severity,
    string Summary,
    bool Triggered,
    string EvidenceJson);

public sealed record GovernanceDecision(
    string DecisionId,
    string DecisionType,
    string Severity,
    string Summary,
    string? SkillName,
    string? EntityType,
    string? EntityId,
    string MetadataJson,
    DateTimeOffset TimestampUtc);

public sealed record ActionExecution(
    string ActionId,
    string ActionType,
    string Severity,
    bool Success,
    bool RequiresApproval,
    string Summary,
    string OutputJson,
    DateTimeOffset TimestampUtc);

public sealed record IncidentState(
    string IncidentId,
    string IncidentType,
    string Severity,
    string Status,
    string Summary,
    string EvidenceJson,
    DateTimeOffset OpenedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? ResolvedAtUtc);

public sealed record GovernanceStatusSnapshot(
    DateTimeOffset TimestampUtc,
    int OpenIncidents,
    int CriticalIncidents,
    int Decisions24h,
    int Actions24h,
    int FailedActions24h,
    double AutoResolutionRate24h);

public sealed record TuningChangeRecord(
    string ChangeId,
    string ParameterName,
    string Scope,
    string BeforeValue,
    string AfterValue,
    string Reason,
    string ImpactExpectation,
    DateTimeOffset TimestampUtc);

public sealed record CanaryRoutingContext(
    string ActionType,
    string? GroupId,
    string? InstanceName,
    string? Channel);

public sealed record CanaryRule(
    string RuleId,
    bool Enabled,
    string ActionType,
    string? GroupId,
    string? InstanceName,
    string? Channel,
    int CanaryPercent);

public sealed record CanaryResolution(
    string Variant,
    string? RuleId,
    int? CanaryPercent);
