using System.Globalization;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Content;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class CsvContentCalendarStore : IContentCalendarStore
{
    private static readonly string[] Header =
    [
        "Id",
        "ScheduledAt",
        "PostType",
        "SourceInput",
        "OfferContext",
        "ReferenceUrl",
        "ReferenceCaption",
        "ReferenceMediaUrl",
        "OfferUrl",
        "Keyword",
        "GeneratedCaption",
        "Hashtags",
        "MediaUrl",
        "AutoPublish",
        "Status",
        "DraftId",
        "PublishedMediaId",
        "Error",
        "Attempts",
        "LastAttemptAt",
        "CreatedAt",
        "UpdatedAt",
        "ProcessingExecutionId",
        "ProcessingClaimedAt"
    ];

    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly InterprocessFileLock _interprocessLock;

    public CsvContentCalendarStore(string? path = null)
    {
        _path = string.IsNullOrWhiteSpace(path) ? Path.Combine(AppContext.BaseDirectory, "data", "content-calendar.csv") : path;
        _interprocessLock = new InterprocessFileLock(_path);
    }

    public async Task<IReadOnlyList<ContentCalendarItem>> ListAsync(CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            return await ReadAllAsync(ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<ContentCalendarItem?> GetAsync(string id, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            var items = await ReadAllAsync(ct);
            return items.FirstOrDefault(x => x.Id == id);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task SaveAsync(ContentCalendarItem item, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            var items = await ReadAllAsync(ct);
            var idx = items.FindIndex(x => x.Id == item.Id);
            if (idx >= 0)
            {
                items[idx] = item;
            }
            else
            {
                items.Add(item);
            }

            await WriteAllAsync(items, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<ContentCalendarItem?> TryClaimDueAsync(string id, string executionId, DateTimeOffset now, int maxAttempts, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            var items = await ReadAllAsync(ct);
            var item = items.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.Ordinal));
            if (item is null || item.ScheduledAt > now || item.Attempts >= maxAttempts ||
                !string.Equals(item.Status, "planned", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            item.Status = "processing";
            item.ProcessingExecutionId = executionId;
            item.ProcessingClaimedAt = now;
            item.Attempts++;
            item.LastAttemptAt = now;
            item.UpdatedAt = now;
            await WriteAllAsync(items, ct);
            return item;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task DeleteAsync(string id, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            var items = await ReadAllAsync(ct);
            items.RemoveAll(x => x.Id == id);
            await WriteAllAsync(items, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<string> ExportCsvAsync(CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            await EnsureFileAsync(ct);
            return await File.ReadAllTextAsync(_path, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<ContentCalendarItem>> ReadAllAsync(CancellationToken ct)
    {
        await EnsureFileAsync(ct);
        var lines = await ReadCsvRecordsAsync(ct);
        if (lines.Count <= 1)
        {
            return [];
        }

        var list = new List<ContentCalendarItem>(lines.Count - 1);
        for (var i = 1; i < lines.Count; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var cols = ParseCsvLine(line);
            if (cols.Count < Header.Length)
            {
                continue;
            }

            list.Add(new ContentCalendarItem
            {
                Id = cols[0],
                ScheduledAt = ParseDate(cols[1], DateTimeOffset.UtcNow),
                PostType = string.IsNullOrWhiteSpace(cols[2]) ? "feed" : cols[2],
                SourceInput = cols[3],
                OfferContext = cols[4],
                ReferenceUrl = cols[5],
                ReferenceCaption = cols[6],
                ReferenceMediaUrl = cols[7],
                OfferUrl = cols[8],
                Keyword = cols[9],
                GeneratedCaption = cols[10],
                Hashtags = cols[11],
                MediaUrl = cols[12],
                AutoPublish = ParseBool(cols[13], true),
                Status = string.IsNullOrWhiteSpace(cols[14]) ? "planned" : cols[14],
                DraftId = NullIfEmpty(cols[15]),
                PublishedMediaId = NullIfEmpty(cols[16]),
                Error = NullIfEmpty(cols[17]),
                Attempts = ParseInt(cols[18]),
                LastAttemptAt = ParseNullableDate(cols[19]),
                CreatedAt = ParseDate(cols[20], DateTimeOffset.UtcNow),
                UpdatedAt = ParseDate(cols[21], DateTimeOffset.UtcNow),
                ProcessingExecutionId = NullIfEmpty(cols[22]),
                ProcessingClaimedAt = ParseNullableDate(cols[23])
            });
        }

        return list
            .OrderBy(x => x.ScheduledAt)
            .ThenBy(x => x.CreatedAt)
            .ToList();
    }

    // A calendar caption may legitimately contain line breaks. Read logical CSV records rather
    // than physical lines so an export can always be imported without silently losing an item.
    private async Task<List<string>> ReadCsvRecordsAsync(CancellationToken ct)
    {
        var records = new List<string>();
        await using var stream = File.OpenRead(_path);
        using var reader = new StreamReader(stream);
        var record = new StringBuilder();
        var inQuotes = false;

        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (record.Length > 0)
            {
                record.Append('\n');
            }

            record.Append(line);
            for (var index = 0; index < line.Length; index++)
            {
                if (line[index] != '"')
                {
                    continue;
                }

                if (inQuotes && index + 1 < line.Length && line[index + 1] == '"')
                {
                    index++;
                    continue;
                }

                inQuotes = !inQuotes;
            }

            if (!inQuotes)
            {
                records.Add(record.ToString());
                record.Clear();
            }
        }

        if (inQuotes)
        {
            throw new InvalidDataException("content-calendar.csv possui um campo CSV sem aspas de fechamento.");
        }

        if (record.Length > 0)
        {
            records.Add(record.ToString());
        }

        return records;
    }

    private async Task WriteAllAsync(List<ContentCalendarItem> items, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', Header.Select(EscapeCsv)));

        foreach (var item in items
                     .OrderBy(x => x.ScheduledAt)
                     .ThenBy(x => x.CreatedAt))
        {
            var cols = new[]
            {
                item.Id,
                FormatDate(item.ScheduledAt),
                item.PostType,
                item.SourceInput,
                item.OfferContext,
                item.ReferenceUrl,
                item.ReferenceCaption,
                item.ReferenceMediaUrl,
                item.OfferUrl,
                item.Keyword,
                item.GeneratedCaption,
                item.Hashtags,
                item.MediaUrl,
                item.AutoPublish ? "true" : "false",
                item.Status,
                item.DraftId ?? string.Empty,
                item.PublishedMediaId ?? string.Empty,
                item.Error ?? string.Empty,
                item.Attempts.ToString(CultureInfo.InvariantCulture),
                FormatNullableDate(item.LastAttemptAt),
                FormatDate(item.CreatedAt),
                FormatDate(item.UpdatedAt),
                item.ProcessingExecutionId ?? string.Empty,
                FormatNullableDate(item.ProcessingClaimedAt)
            };

            sb.AppendLine(string.Join(',', cols.Select(EscapeCsv)));
        }

        var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
        await File.WriteAllTextAsync(tempPath, sb.ToString(), ct);
        File.Move(tempPath, _path, true);
    }

    private async Task EnsureFileAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        if (File.Exists(_path))
        {
            return;
        }

        var headerLine = string.Join(',', Header.Select(EscapeCsv)) + Environment.NewLine;
        await File.WriteAllTextAsync(_path, headerLine, ct);
    }

    private static string EscapeCsv(string value)
    {
        var text = value ?? string.Empty;
        var needsQuotes = text.Contains(',') || text.Contains('"') || text.Contains('\n') || text.Contains('\r');
        if (!needsQuotes)
        {
            return text;
        }

        return $"\"{text.Replace("\"", "\"\"")}\"";
    }

    private static List<string> ParseCsvLine(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                    continue;
                }

                inQuotes = !inQuotes;
                continue;
            }

            if (c == ',' && !inQuotes)
            {
                result.Add(sb.ToString());
                sb.Clear();
                continue;
            }

            sb.Append(c);
        }

        result.Add(sb.ToString());
        while (result.Count < Header.Length)
        {
            result.Add(string.Empty);
        }

        return result;
    }

    private static DateTimeOffset ParseDate(string value, DateTimeOffset fallback)
        => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt)
            ? dt
            : fallback;

    private static DateTimeOffset? ParseNullableDate(string value)
        => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt)
            ? dt
            : null;

    private static string FormatDate(DateTimeOffset value)
        => value.ToString("O", CultureInfo.InvariantCulture);

    private static string FormatNullableDate(DateTimeOffset? value)
        => value.HasValue ? value.Value.ToString("O", CultureInfo.InvariantCulture) : string.Empty;

    private static int ParseInt(string value)
        => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0;

    private static bool ParseBool(string value, bool fallback)
        => bool.TryParse(value, out var b) ? b : fallback;

    private static string? NullIfEmpty(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;
}
