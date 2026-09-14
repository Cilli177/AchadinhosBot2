namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public sealed record InstagramWhatsAppCommand(string Action, string? Argument);
public sealed record InstagramCaptionChoiceCommand(int OptionNumber, string DraftRef);

public static class InstagramWhatsAppCommandParser
{
    public static bool TryParse(string text, out InstagramWhatsAppCommand command)
    {
        command = new InstagramWhatsAppCommand("unknown", null);
        if (string.IsNullOrWhiteSpace(text)) return false;

        var trimmed = text.Trim();
        string payload;
        if (trimmed.StartsWith("/ig", StringComparison.OrdinalIgnoreCase)) payload = trimmed[3..].Trim();
        else if (trimmed.StartsWith("ig ", StringComparison.OrdinalIgnoreCase)) payload = trimmed[2..].Trim();
        else return false;

        if (string.IsNullOrWhiteSpace(payload))
        {
            command = new InstagramWhatsAppCommand("help", null);
            return true;
        }

        var parts = payload.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var action = parts[0].ToLowerInvariant();
        var argument = parts.Length > 1 ? parts[1].Trim() : null;
        command = action switch
        {
            "criar" or "novo" => new("create", argument),
            "rapido" or "fluxo" or "turbo" => new("create_fast", argument),
            "imagem" or "img" or "midia" => new("add_images", argument),
            "imagens" or "fotos" or "galeria" => new("manage_images", argument),
            "limpar-imagens" or "limparimagens" or "limpar-midias" or "limparmidias" => new("clear_images", argument),
            "tipo" or "modo" => new("set_type", argument),
            "formatar" or "format" => new("format_caption", argument),
            "leg" => new("pick_caption", argument),
            "cta" => new("set_cta", argument),
            "anunciar" or "boost" or "promover" => new("boost_post", argument),
            "templates" => new("list_templates", argument),
            "template" or "modelo" => new("apply_template", argument),
            "menu" or "opcoes" or "atalhos" => new("menu", argument),
            "legenda" or "caption" or "texto" => new("set_caption", argument),
            "revisar" or "status" => new("review", argument),
            "confirmar" or "publicar" => new("confirm", argument),
            "reset" or "zerar" or "reiniciar" => new("reset", argument),
            "ajuda" or "help" => new("help", argument),
            _ => new("unknown", payload)
        };
        return true;
    }

    public static bool TryParseCaptionChoice(string text, out InstagramCaptionChoiceCommand command)
    {
        command = new InstagramCaptionChoiceCommand(0, "ultimo");
        if (string.IsNullOrWhiteSpace(text)) return false;

        var parts = text.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2 || !new[] { "/leg", "\\leg", "leg" }.Contains(parts[0], StringComparer.OrdinalIgnoreCase) || !int.TryParse(parts[1], out var option) || option <= 0) return false;

        command = new InstagramCaptionChoiceCommand(option, parts.Length >= 3 ? parts[2] : "ultimo");
        return true;
    }
}
