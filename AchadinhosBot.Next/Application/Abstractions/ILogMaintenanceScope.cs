namespace AchadinhosBot.Next.Application.Abstractions;

public interface ILogMaintenanceScope
{
    string ScopeId { get; }
    IReadOnlyList<string> RelativePaths { get; }
}

public interface ILogMaintenanceLockCoordinator
{
    ValueTask<IAsyncDisposable> AcquireAsync(string scopeId, CancellationToken cancellationToken);
}
