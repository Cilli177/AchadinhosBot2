namespace AchadinhosBot.Next.Configuration;

public sealed class GovernanceOptions
{
    public bool Enabled { get; set; } = true;
    public bool SchedulerEnabled { get; set; } = true;
    public bool AutoHealingEnabled { get; set; } = true;
    public bool AutoTuningEnabled { get; set; } = true;
    public bool AutoRollbackEnabled { get; set; } = true;
    public bool AllowDestructiveActions { get; set; } = false;
    public bool ShadowMode { get; set; } = true;
    public int SchedulerIntervalSeconds { get; set; } = 30;
    public int MaxActionsPerWindow { get; set; } = 10;
    public int ActionWindowMinutes { get; set; } = 15;
    public int CriticalOutboxBacklogThreshold { get; set; } = 25;
    public int WorkerStaleAfterSeconds { get; set; } = 180;
    public int DependencyFailureThreshold { get; set; } = 3;
}
