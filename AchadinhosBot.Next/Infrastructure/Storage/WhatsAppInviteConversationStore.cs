using System.Text.Json;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class WhatsAppInviteConversationStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public WhatsAppInviteConversationStore()
    {
        var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
        _path = Path.Combine(dataDir, "whatsapp-invite-conversations.json");
    }

    public async Task StartAsync(string? instanceName, string participantId, string sourceScheduleId, CancellationToken cancellationToken)
    {
        var key = BuildKey(instanceName, participantId);
        var now = DateTimeOffset.UtcNow;

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateUnsafeAsync(cancellationToken);
            state[key] = new WhatsAppInviteConversationState
            {
                InstanceName = Normalize(instanceName),
                ParticipantId = NormalizeParticipant(participantId),
                SourceScheduleId = sourceScheduleId.Trim(),
                AwaitingChoice = true,
                StartedAt = now,
                LastUpdatedAt = now
            };

            await SaveStateUnsafeAsync(state, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<WhatsAppInviteConversationState?> GetAsync(string? instanceName, string participantId, CancellationToken cancellationToken)
    {
        var key = BuildKey(instanceName, participantId);

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateUnsafeAsync(cancellationToken);
            return state.TryGetValue(key, out var entry) ? entry : null;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task MarkLinkSentAsync(string? instanceName, string participantId, string slug, CancellationToken cancellationToken)
    {
        var key = BuildKey(instanceName, participantId);
        var normalizedSlug = Normalize(slug);
        var now = DateTimeOffset.UtcNow;

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateUnsafeAsync(cancellationToken);
            if (!state.TryGetValue(key, out var entry))
            {
                return;
            }

            if (!entry.SentSlugs.Any(x => string.Equals(x, normalizedSlug, StringComparison.OrdinalIgnoreCase)))
            {
                entry.SentSlugs.Add(normalizedSlug);
            }

            entry.AwaitingChoice = true;
            entry.LastUpdatedAt = now;
            state[key] = entry;
            await SaveStateUnsafeAsync(state, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task ClearAsync(string? instanceName, string participantId, CancellationToken cancellationToken)
    {
        var key = BuildKey(instanceName, participantId);

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateUnsafeAsync(cancellationToken);
            if (state.Remove(key))
            {
                await SaveStateUnsafeAsync(state, cancellationToken);
            }
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<Dictionary<string, WhatsAppInviteConversationState>> LoadStateUnsafeAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new Dictionary<string, WhatsAppInviteConversationState>(StringComparer.OrdinalIgnoreCase);
            }

            var json = await File.ReadAllTextAsync(_path, cancellationToken);
            return JsonSerializer.Deserialize<Dictionary<string, WhatsAppInviteConversationState>>(json)
                ?? new Dictionary<string, WhatsAppInviteConversationState>(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, WhatsAppInviteConversationState>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private async Task SaveStateUnsafeAsync(Dictionary<string, WhatsAppInviteConversationState> state, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_path, json, cancellationToken);
    }

    private static string BuildKey(string? instanceName, string participantId)
        => $"{Normalize(instanceName)}|{NormalizeParticipant(participantId)}";

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
}

public sealed class WhatsAppInviteConversationState
{
    public string InstanceName { get; set; } = string.Empty;
    public string ParticipantId { get; set; } = string.Empty;
    public string SourceScheduleId { get; set; } = string.Empty;
    public bool AwaitingChoice { get; set; }
    public List<string> SentSlugs { get; set; } = new();
    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastUpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
