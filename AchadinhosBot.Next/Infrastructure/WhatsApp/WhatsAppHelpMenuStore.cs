namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public sealed class WhatsAppHelpMenuStore
{
    private readonly Dictionary<string, DateTimeOffset> _armedChats = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _ttl = TimeSpan.FromMinutes(20);
    private readonly object _sync = new();

    public void Arm(string chatId)
    {
        if (string.IsNullOrWhiteSpace(chatId))
        {
            return;
        }

        lock (_sync)
        {
            CleanupLocked();
            _armedChats[chatId] = DateTimeOffset.UtcNow;
        }
    }

    public void Disarm(string chatId)
    {
        if (string.IsNullOrWhiteSpace(chatId))
        {
            return;
        }

        lock (_sync)
        {
            _armedChats.Remove(chatId);
        }
    }

    public bool TryResolveScope(string chatId, string? text, out string scope)
    {
        scope = string.Empty;
        if (string.IsNullOrWhiteSpace(chatId) || string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        lock (_sync)
        {
            CleanupLocked();
            if (!_armedChats.ContainsKey(chatId))
            {
                return false;
            }
        }

        if (!TryMapScope(text, out var mappedScope))
        {
            return false;
        }

        lock (_sync)
        {
            // Mantem o menu ativo para permitir varias consultas sem repetir /help.
            _armedChats[chatId] = DateTimeOffset.UtcNow;
        }

        scope = mappedScope;
        return true;
    }

    private void CleanupLocked()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = _armedChats
            .Where(x => now - x.Value > _ttl)
            .Select(x => x.Key)
            .ToList();
        foreach (var key in expired)
        {
            _armedChats.Remove(key);
        }
    }

    private static bool TryMapScope(string text, out string scope)
    {
        scope = string.Empty;
        var normalized = text.Trim().ToLowerInvariant();
        scope = normalized switch
        {
            "1" => "instagram",
            "2" => "cta",
            "3" => "links",
            "4" => "ads",
            "5" => "quick",
            _ => string.Empty
        };

        return !string.IsNullOrWhiteSpace(scope);
    }
}
