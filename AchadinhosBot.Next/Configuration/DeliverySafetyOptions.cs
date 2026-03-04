namespace AchadinhosBot.Next.Configuration;

public sealed class DeliverySafetyOptions
{
    public bool BlockOfficialDestinationsOutsideProduction { get; init; } = true;
    public bool BlockOfficialWhatsAppAlways { get; init; } = false;
    public List<string> OfficialWhatsAppGroupIds { get; init; } = new();
    public List<long> OfficialTelegramChatIds { get; init; } = new();
}
