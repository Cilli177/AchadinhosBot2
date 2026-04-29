using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class WhatsAppGroupMembershipStore : IWhatsAppGroupMembershipStore
{
    private readonly string _path;
    private readonly string _statePath;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public WhatsAppGroupMembershipStore()
    {
        var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
        _path = Path.Combine(dataDir, "whatsapp-membership-events.jsonl");
        _statePath = Path.Combine(dataDir, "whatsapp-membership-state.json");
    }

    public async Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, CancellationToken cancellationToken)
        => await GetParticipantsAsync(groupId, instanceName: null, cancellationToken);

    public async Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, string? instanceName, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_statePath)) return Array.Empty<string>();
            var json = await File.ReadAllTextAsync(_statePath, cancellationToken);
            var state = JsonSerializer.Deserialize<Dictionary<string, List<string>>>(json);
            var stateKey = BuildStateKey(groupId, instanceName);
            if (state != null && state.TryGetValue(stateKey, out var list)) return list.AsReadOnly();

            // Backward compatibility: legacy key without instance name.
            if (string.IsNullOrWhiteSpace(instanceName) && state != null && state.TryGetValue(groupId, out var legacyList))
                return legacyList.AsReadOnly();

            return Array.Empty<string>();
        }
        catch
        {
            return Array.Empty<string>();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task SetParticipantsAsync(string groupId, IEnumerable<string> participants, CancellationToken cancellationToken)
        => await SetParticipantsAsync(groupId, instanceName: null, participants, cancellationToken);

    public async Task SetParticipantsAsync(string groupId, string? instanceName, IEnumerable<string> participants, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Dictionary<string, List<string>> state;
            if (File.Exists(_statePath))
            {
                var json = await File.ReadAllTextAsync(_statePath, cancellationToken);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    try
                    {
                        state = JsonSerializer.Deserialize<Dictionary<string, List<string>>>(json) ?? new();
                    }
                    catch
                    {
                        state = new();
                    }
                }
                else
                {
                    state = new();
                }
            }
            else
            {
                state = new();
            }

            var stateKey = BuildStateKey(groupId, instanceName);
            state[stateKey] = participants.ToList();
            var newJson = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            await File.WriteAllTextAsync(_statePath, newJson, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task AppendAsync(WhatsAppGroupMembershipEvent @event, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var line = JsonSerializer.Serialize(@event) + Environment.NewLine;
            await File.AppendAllTextAsync(_path, line, cancellationToken);
            await JsonlLogRetention.TrimIfNeededAsync(_path, 5000, 5 * 1024 * 1024, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<WhatsAppGroupMembershipEvent>> ListAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<WhatsAppGroupMembershipEvent>();
            }

            var lines = await File.ReadAllLinesAsync(_path, cancellationToken);
            return lines
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(TryDeserialize)
                .Where(x => x is not null)
                .Cast<WhatsAppGroupMembershipEvent>()
                .OrderByDescending(x => x.Timestamp)
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    private static WhatsAppGroupMembershipEvent? TryDeserialize(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<WhatsAppGroupMembershipEvent>(line);
        }
        catch
        {
            return null;
        }
    }

    private static string BuildStateKey(string groupId, string? instanceName)
    {
        var normalizedGroup = (groupId ?? string.Empty).Trim();
        var normalizedInstance = string.IsNullOrWhiteSpace(instanceName) ? "default" : instanceName.Trim();
        return $"{normalizedInstance}:{normalizedGroup}";
    }
}
