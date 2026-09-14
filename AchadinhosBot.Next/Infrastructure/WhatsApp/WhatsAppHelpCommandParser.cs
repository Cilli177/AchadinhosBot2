namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public static class WhatsAppHelpCommandParser
{
    public static bool TryParse(string text, out string scope)
    {
        scope = "general";
        if (string.IsNullOrWhiteSpace(text)) return false;

        var normalized = text.Trim();
        var firstToken = normalized.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? string.Empty;
        var isHelp = string.Equals(firstToken, @"\help", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(firstToken, "/help", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(firstToken, "/ajuda", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(normalized, "help", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(normalized, "ajuda", StringComparison.OrdinalIgnoreCase);
        if (!isHelp) return false;

        var scopeToken = normalized.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Skip(1).FirstOrDefault() ?? "general";
        scope = scopeToken.ToLowerInvariant() switch
        {
            "1" or "ig" or "insta" or "instagram" => "instagram",
            "2" or "cta" or "comentarios" => "cta",
            "3" or "link" or "links" or "bio" => "links",
            "4" or "ad" or "ads" or "anuncio" or "anuncios" => "ads",
            "5" or "rapido" or "atalhos" => "quick",
            _ => "general"
        };
        return true;
    }
}
