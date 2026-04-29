namespace AchadinhosBot.Next.Application.Services;

public static class WhatsAppInstanceRoutingPolicy
{
    public const string OfficialOffersInstance = "ZapOfertas";
    public const string ParticipantOpsInstance = "ZapOfertas2";

    public static bool IsOfficialOffersInstance(string? instanceName)
    {
        return string.Equals(
            Normalize(instanceName),
            OfficialOffersInstance,
            StringComparison.OrdinalIgnoreCase);
    }

    public static string ResolveParticipantOpsInstance(string? instanceName)
    {
        var normalized = Normalize(instanceName);
        if (!string.IsNullOrWhiteSpace(normalized))
        {
            return normalized;
        }

        return ParticipantOpsInstance;
    }

    private static string? Normalize(string? instanceName)
    {
        return string.IsNullOrWhiteSpace(instanceName) ? null : instanceName.Trim();
    }
}
