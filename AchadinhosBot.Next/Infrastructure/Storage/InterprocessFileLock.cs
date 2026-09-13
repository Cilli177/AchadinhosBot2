namespace AchadinhosBot.Next.Infrastructure.Storage;

/// <summary>Exclusive file lock shared by processes using the same mounted data directory.</summary>
public sealed class InterprocessFileLock
{
    private readonly string _path;

    public InterprocessFileLock(string protectedPath) => _path = $"{protectedPath}.lock";

    public async Task<IAsyncDisposable> AcquireAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new Handle(new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.Asynchronous));
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(75), ct);
            }
        }
    }

    private sealed class Handle(FileStream stream) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => stream.DisposeAsync();
    }
}
