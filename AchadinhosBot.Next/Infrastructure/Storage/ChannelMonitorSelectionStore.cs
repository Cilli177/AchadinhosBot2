using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class ChannelMonitorSelectionStore : IChannelMonitorSelectionStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public ChannelMonitorSelectionStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "channel-monitor-selections.json");
    }

    public async Task<IReadOnlyList<ChannelMonitorSelectionEntry>> ListBySourceAsync(string sourceChannel, CancellationToken cancellationToken)
    {
        var normalized = NormalizeSourceChannel(sourceChannel);
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            return all
                .Where(x => string.Equals(x.SourceChannel, normalized, StringComparison.OrdinalIgnoreCase))
                .OrderBy(x => x.Title, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.ChatId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<ChannelMonitorSelectionEntry>> ReplaceSelectionsAsync(
        string sourceChannel,
        IEnumerable<ChannelMonitorSelectionEntry> selections,
        CancellationToken cancellationToken)
    {
        var normalized = NormalizeSourceChannel(sourceChannel);
        var incoming = (selections ?? Array.Empty<ChannelMonitorSelectionEntry>())
            .Where(x => !string.IsNullOrWhiteSpace(x.ChatId))
            .GroupBy(x => x.ChatId.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            var existingByChatId = all
                .Where(x => string.Equals(x.SourceChannel, normalized, StringComparison.OrdinalIgnoreCase))
                .ToDictionary(x => x.ChatId, StringComparer.OrdinalIgnoreCase);

            all.RemoveAll(x => string.Equals(x.SourceChannel, normalized, StringComparison.OrdinalIgnoreCase));

            foreach (var item in incoming)
            {
                var chatId = item.ChatId.Trim();
                var existing = existingByChatId.TryGetValue(chatId, out var stored) ? stored : null;
                all.Add(new ChannelMonitorSelectionEntry
                {
                    SourceChannel = normalized,
                    ChatId = chatId,
                    Title = string.IsNullOrWhiteSpace(item.Title) ? chatId : item.Title.Trim(),
                    SelectedAtUtc = existing?.SelectedAtUtc ?? DateTimeOffset.UtcNow
                });
            }

            await WriteAllUnsafeAsync(all, cancellationToken);

            return all
                .Where(x => string.Equals(x.SourceChannel, normalized, StringComparison.OrdinalIgnoreCase))
                .OrderBy(x => x.Title, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.ChatId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<ChannelMonitorSelectionEntry>> ReadAllUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new List<ChannelMonitorSelectionEntry>();
        }

        try
        {
            var json = await File.ReadAllTextAsync(_path, cancellationToken);
            return JsonSerializer.Deserialize<List<ChannelMonitorSelectionEntry>>(json) ?? new List<ChannelMonitorSelectionEntry>();
        }
        catch
        {
            return new List<ChannelMonitorSelectionEntry>();
        }
    }

    private async Task WriteAllUnsafeAsync(List<ChannelMonitorSelectionEntry> items, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var json = JsonSerializer.Serialize(items.OrderBy(x => x.SourceChannel).ThenBy(x => x.Title).ThenBy(x => x.ChatId));
        await File.WriteAllTextAsync(_path, json, cancellationToken);
    }

    private static string NormalizeSourceChannel(string? sourceChannel)
        => string.Equals(sourceChannel?.Trim(), "whatsapp", StringComparison.OrdinalIgnoreCase) ? "whatsapp" : "telegram";
}
