using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class ChannelOfferCandidateStore : IChannelOfferCandidateStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public ChannelOfferCandidateStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "channel-offer-candidates.json");
    }

    public async Task UpsertManyAsync(IEnumerable<ChannelOfferCandidate> candidates, CancellationToken cancellationToken)
    {
        var incoming = (candidates ?? Array.Empty<ChannelOfferCandidate>())
            .Where(x => !string.IsNullOrWhiteSpace(x.SourceChannel) && !string.IsNullOrWhiteSpace(x.MessageId))
            .ToArray();

        if (incoming.Length == 0)
        {
            return;
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            var byKey = all.ToDictionary(BuildKey, StringComparer.OrdinalIgnoreCase);
            foreach (var item in incoming)
            {
                byKey[BuildKey(item)] = item;
            }

            var payload = byKey.Values
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(5000)
                .ToArray();
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var json = JsonSerializer.Serialize(payload);
            await File.WriteAllTextAsync(_path, json, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<ChannelOfferCandidate?> GetAsync(string sourceChannel, string messageId, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            return all.FirstOrDefault(x =>
                string.Equals(x.SourceChannel, sourceChannel, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.MessageId, messageId, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<ChannelOfferCandidate>> ReadAllUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new List<ChannelOfferCandidate>();
        }

        try
        {
            var json = await File.ReadAllTextAsync(_path, cancellationToken);
            return JsonSerializer.Deserialize<List<ChannelOfferCandidate>>(json) ?? new List<ChannelOfferCandidate>();
        }
        catch
        {
            return new List<ChannelOfferCandidate>();
        }
    }

    private static string BuildKey(ChannelOfferCandidate candidate)
        => $"{candidate.SourceChannel}:{candidate.MessageId}";
}
