namespace AchadinhosBot.Next.Infrastructure.Storage;

internal static class VersionRetentionPolicy
{
    public static void Prune(string versionsDirectory, string searchPattern, int keepCount)
    {
        if (keepCount < 1 || !Directory.Exists(versionsDirectory))
        {
            return;
        }

        var files = new DirectoryInfo(versionsDirectory)
            .EnumerateFiles(searchPattern, SearchOption.TopDirectoryOnly)
            .OrderByDescending(x => x.LastWriteTimeUtc)
            .ThenByDescending(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var retained = 0;
        foreach (var file in files)
        {
            if (file.Length > 0 && retained < keepCount)
            {
                retained++;
                continue;
            }

            file.Delete();
        }
    }
}
