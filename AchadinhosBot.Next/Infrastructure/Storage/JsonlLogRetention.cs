namespace AchadinhosBot.Next.Infrastructure.Storage;

public static class JsonlLogRetention
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTimeOffset> LastTrimAttempts = new(StringComparer.OrdinalIgnoreCase);

    public static async Task TrimIfNeededAsync(string path, int maxLines, long maxBytes, CancellationToken ct)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var info = new FileInfo(path);
        if (info.Length <= maxBytes)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (LastTrimAttempts.TryGetValue(path, out var lastAttempt) &&
            now - lastAttempt < TimeSpan.FromMinutes(2))
        {
            return;
        }

        LastTrimAttempts[path] = now;

        var lines = await File.ReadAllLinesAsync(path, ct);
        if (lines.Length <= maxLines)
        {
            return;
        }

        var keep = lines.Skip(lines.Length - maxLines).ToArray();
        await File.WriteAllLinesAsync(path, keep, ct);
    }
}
