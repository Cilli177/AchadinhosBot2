using System.Text.Json;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class WhatsAppWelcomeJourneyStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public WhatsAppWelcomeJourneyStore()
    {
        var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
        _path = Path.Combine(dataDir, "whatsapp-welcome-journey.json");
    }

    public async Task<bool> ShouldSendWelcomeAsync(
        string? instanceName,
        string groupId,
        string participantId,
        TimeSpan cooldown,
        CancellationToken cancellationToken)
    {
        var key = BuildKey(instanceName, groupId, participantId);
        var now = DateTimeOffset.UtcNow;

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateUnsafeAsync(cancellationToken);
            if (!state.TryGetValue(key, out var entry) || entry.WelcomeSentAt is null)
            {
                return true;
            }

            return now - entry.WelcomeSentAt.Value >= cooldown;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task MarkWelcomeSentAsync(
        string? instanceName,
        string groupId,
        string participantId,
        bool awaitingAffirmative,
        CancellationToken cancellationToken)
    {
        var key = BuildKey(instanceName, groupId, participantId);
        var now = DateTimeOffset.UtcNow;

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateUnsafeAsync(cancellationToken);
            var entry = state.TryGetValue(key, out var existing)
                ? existing
                : new WelcomeJourneyState();

            entry.InstanceName = Normalize(instanceName);
            entry.GroupId = Normalize(groupId);
            entry.Participant = NormalizeParticipant(participantId);
            entry.WelcomeSentAt = now;
            entry.AwaitingAffirmative = awaitingAffirmative;
            entry.FollowUpSentAt = null;
            entry.LastUpdatedAt = now;

            state[key] = entry;
            await SaveStateUnsafeAsync(state, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<bool> TryConsumeAffirmativeAsync(
        string participantId,
        TimeSpan maxWindow,
        CancellationToken cancellationToken)
    {
        var normalizedParticipant = NormalizeParticipant(participantId);
        var now = DateTimeOffset.UtcNow;

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateUnsafeAsync(cancellationToken);
            var selectedKey = state
                .Where(kvp =>
                    string.Equals(kvp.Value.Participant, normalizedParticipant, StringComparison.OrdinalIgnoreCase) &&
                    kvp.Value.AwaitingAffirmative &&
                    kvp.Value.WelcomeSentAt is not null &&
                    now - kvp.Value.WelcomeSentAt.Value <= maxWindow)
                .OrderByDescending(kvp => kvp.Value.WelcomeSentAt)
                .Select(kvp => kvp.Key)
                .FirstOrDefault();

            if (string.IsNullOrWhiteSpace(selectedKey) || !state.TryGetValue(selectedKey, out var selectedEntry))
            {
                return false;
            }

            selectedEntry.AwaitingAffirmative = false;
            selectedEntry.FollowUpSentAt = now;
            selectedEntry.LastUpdatedAt = now;
            state[selectedKey] = selectedEntry;
            await SaveStateUnsafeAsync(state, cancellationToken);
            return true;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<Dictionary<string, WelcomeJourneyState>> LoadStateUnsafeAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new Dictionary<string, WelcomeJourneyState>(StringComparer.OrdinalIgnoreCase);
            }

            var json = await File.ReadAllTextAsync(_path, cancellationToken);
            return JsonSerializer.Deserialize<Dictionary<string, WelcomeJourneyState>>(json)
                ?? new Dictionary<string, WelcomeJourneyState>(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, WelcomeJourneyState>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private async Task SaveStateUnsafeAsync(Dictionary<string, WelcomeJourneyState> state, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_path, json, cancellationToken);
    }

    private static string BuildKey(string? instanceName, string groupId, string participantId)
        => $"{Normalize(instanceName)}|{Normalize(groupId)}|{NormalizeParticipant(participantId)}";

    private static string Normalize(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();

    private static string NormalizeParticipant(string? value)
    {
        var normalized = Normalize(value);
        var atIndex = normalized.IndexOf('@');
        if (atIndex > 0)
        {
            normalized = normalized[..atIndex];
        }

        return normalized;
    }

    private sealed class WelcomeJourneyState
    {
        public string InstanceName { get; set; } = string.Empty;
        public string GroupId { get; set; } = string.Empty;
        public string Participant { get; set; } = string.Empty;
        public DateTimeOffset? WelcomeSentAt { get; set; }
        public bool AwaitingAffirmative { get; set; }
        public DateTimeOffset? FollowUpSentAt { get; set; }
        public DateTimeOffset LastUpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    }
}
