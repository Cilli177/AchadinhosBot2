namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramCommandMenuStore
{
    private readonly Dictionary<string, DateTimeOffset> _armedChats = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _ttl = TimeSpan.FromMinutes(15);
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

    public bool TryResolveSelection(string chatId, string? text, out string commandText)
    {
        commandText = string.Empty;
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

        if (!TryParseMenuOption(text, out var option))
        {
            return false;
        }

        var mapped = MapOptionToCommand(option);
        if (string.IsNullOrWhiteSpace(mapped))
        {
            return false;
        }

        lock (_sync)
        {
            _armedChats.Remove(chatId);
        }

        commandText = mapped!;
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

    private static bool TryParseMenuOption(string text, out int option)
    {
        option = 0;
        var normalized = text.Trim();
        if (!int.TryParse(normalized, out option))
        {
            return false;
        }

        return option is >= 1 and <= 8;
    }

    private static string? MapOptionToCommand(int option)
    {
        return option switch
        {
            1 => "/ig revisar ultimo",
            2 => "/ig confirmar ultimo",
            3 => "/ig formatar ultimo",
            4 => "/ig template ultimo 1",
            5 => "/ig template ultimo 2",
            6 => "/ig template ultimo 3",
            7 => "/ig templates",
            8 => "/ig ajuda",
            _ => null
        };
    }
}
