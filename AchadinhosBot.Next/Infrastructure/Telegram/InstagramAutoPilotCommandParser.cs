using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Telegram;

public static class InstagramAutoPilotCommandParser
{
    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static (InstagramAutoPilotRunRequest? Request, string? ErrorMessage, string StatusMessage) ParseManualCommand(
        string commandName,
        IReadOnlyList<string> arguments,
        long chatId)
    {
        var normalized = string.Equals(commandName, "story", StringComparison.OrdinalIgnoreCase) ? "story" : "feed";
        var safeArguments = arguments ?? Array.Empty<string>();
        var argsText = string.Join(" ", safeArguments);
        var manualUrl = UrlRegex.Match(argsText).Value;
        if (string.IsNullOrWhiteSpace(manualUrl))
        {
            var errorMessage = normalized == "story"
                ? "Para postagem direta no Story, forneca um link. Ex: /story https://...\nPara rodar o ranking automatico, use /autostory"
                : "Para postagem direta no Feed, forneca um link. Ex: /post https://...\nPara rodar o ranking automatico, use /autopilot";
            return (null, errorMessage, string.Empty);
        }

        var dryRun = safeArguments.Any(x =>
            string.Equals(x, "dry", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(x, "teste", StringComparison.OrdinalIgnoreCase));

        var request = new InstagramAutoPilotRunRequest
        {
            PostType = normalized,
            ManualUrl = manualUrl,
            DryRun = dryRun,
            SendForApproval = !dryRun,
            ApprovalChannel = "telegram",
            ApprovalTelegramChatId = chatId
        };

        var statusMessage = normalized == "story"
            ? "Executando criacao de story para o link fornecido..."
            : "Executando criacao de post para o link fornecido...";
        if (dryRun)
        {
            statusMessage += " (dry-run)";
        }

        return (request, null, statusMessage);
    }
}
