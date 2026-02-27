namespace AchadinhosBot.Next.Infrastructure.Storage;

public static class JsonlLogRetention
{
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

        var lines = await File.ReadAllLinesAsync(path, ct);
        if (lines.Length <= maxLines)
        {
            return;
        }

        var keep = lines.Skip(lines.Length - maxLines).ToArray();
        await File.WriteAllLinesAsync(path, keep, ct);
    }
}
