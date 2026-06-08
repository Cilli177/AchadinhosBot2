namespace AchadinhosBot.Next.Application.Services;

internal static class InstagramCommandParser
{
    internal static string NormalizeInstagramPostTypeValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "feed";
        }

        var normalized = value.Trim().ToLowerInvariant();
        if (normalized.StartsWith("story", StringComparison.OrdinalIgnoreCase) || normalized == "stories")
        {
            return "story";
        }

        if (normalized.StartsWith("reel", StringComparison.OrdinalIgnoreCase))
        {
            return "reel";
        }

        return "feed";
    }

    internal static InstagramTypeCommandInput ParseInstagramTypeCommandInput(string? argument)
    {
        if (string.IsNullOrWhiteSpace(argument))
        {
            return new InstagramTypeCommandInput("ultimo", "feed", "Uso: /ig tipo <id|ultimo> <feed|story|reel>");
        }

        var parts = argument.Trim()
            .Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        string draftRef;
        string requestedType;
        if (parts.Length == 1)
        {
            draftRef = "ultimo";
            requestedType = parts[0];
        }
        else
        {
            draftRef = parts[0];
            requestedType = parts[1];
        }

        var normalized = NormalizeInstagramPostTypeValue(requestedType);
        return new InstagramTypeCommandInput(draftRef, normalized, null);
    }
}
