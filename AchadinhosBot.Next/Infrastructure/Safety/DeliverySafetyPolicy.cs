using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Safety;

public sealed class DeliverySafetyPolicy
{
    private readonly IHostEnvironment _environment;
    private readonly DeliverySafetyOptions _options;

    public DeliverySafetyPolicy(
        IHostEnvironment environment,
        IOptions<DeliverySafetyOptions> options)
    {
        _environment = environment;
        _options = options.Value;
    }

    public bool IsWhatsAppDestinationAllowed(string? chatId, out string? reason)
    {
        reason = null;
        if (string.IsNullOrWhiteSpace(chatId))
        {
            return true;
        }

        var normalized = chatId.Trim();
        var isOfficial = IsOfficialWhatsAppDestination(normalized);

        if (_options.BlockOfficialWhatsAppAlways && isOfficial)
        {
            reason = $"Bloqueado por seguranca: destino oficial WhatsApp '{normalized}'.";
            return false;
        }

        if (isOfficial)
        {
            return true;
        }

        return true;
    }

    public bool IsOfficialWhatsAppDestination(string? chatId)
    {
        if (string.IsNullOrWhiteSpace(chatId))
        {
            return false;
        }

        var normalized = chatId.Trim();
        if (_options.OfficialWhatsAppGroupIds
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Any(x => string.Equals(normalized, x.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var configured = Environment.GetEnvironmentVariable("OFFICIAL_WHATSAPP_GROUP_ID");
        return !string.IsNullOrWhiteSpace(configured) &&
               string.Equals(configured.Trim(), normalized, StringComparison.OrdinalIgnoreCase);
    }

    public bool IsTelegramDestinationAllowed(long chatId, out string? reason)
    {
        reason = null;
        if (chatId == 0)
        {
            return true;
        }

        if (!ShouldRestrictOutsideProduction())
        {
            return true;
        }

        if (_options.OfficialTelegramChatIds.Contains(chatId))
        {
            reason = $"Bloqueado por seguranca: destino oficial Telegram '{chatId}' em ambiente '{_environment.EnvironmentName}'.";
            return false;
        }

        return true;
    }

    private bool ShouldRestrictOutsideProduction()
        => _options.BlockOfficialDestinationsOutsideProduction && !_environment.IsProduction();
}
