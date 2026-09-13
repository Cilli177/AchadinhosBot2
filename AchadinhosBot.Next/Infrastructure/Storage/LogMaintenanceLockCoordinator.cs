using System.Collections.Concurrent;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class LogMaintenanceLockCoordinator : ILogMaintenanceLockCoordinator
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.Ordinal);
    private readonly string _lockDirectory;

    public LogMaintenanceLockCoordinator(string? dataRoot = null)
    {
        _lockDirectory = Path.Combine(Path.GetFullPath(dataRoot ?? Path.Combine(AppContext.BaseDirectory, "data")), "log-maintenance-locks");
    }

    public async ValueTask<IAsyncDisposable> AcquireAsync(string scopeId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(scopeId) || scopeId.Any(static ch => !(char.IsLetterOrDigit(ch) || ch is '-' or '_')))
            throw new ArgumentException("Scope is required and may contain only letters, numbers, hyphens, and underscores.", nameof(scopeId));
        var normalizedScope = scopeId.Trim();
        var gate = _locks.GetOrAdd(normalizedScope, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        FileStream? lockFile = null;
        try
        {
            Directory.CreateDirectory(_lockDirectory);
            var lockPath = Path.Combine(_lockDirectory, $"{normalizedScope}.lock");
            while (lockFile is null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try { lockFile = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.Asynchronous); }
                catch (IOException) { await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken); }
            }
            return new Releaser(gate, lockFile);
        }
        catch
        {
            lockFile?.Dispose();
            gate.Release();
            throw;
        }
    }

    private sealed class Releaser(SemaphoreSlim gate, FileStream lockFile) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() { lockFile.Dispose(); gate.Release(); return ValueTask.CompletedTask; }
    }
}
