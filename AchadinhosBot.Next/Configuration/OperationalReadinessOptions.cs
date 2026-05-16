namespace AchadinhosBot.Next.Configuration;

public sealed class OperationalReadinessOptions
{
    public int WorkerStaleAfterSeconds { get; init; } = 180;

    public int CriticalOutboxBacklog { get; init; } = 25;

    public int DependencyTimeoutSeconds { get; init; } = 5;

    public bool RequireEvolutionReady { get; init; } = true;

    public string[] AllowedEvolutionStates { get; init; } = ["open"];
}
