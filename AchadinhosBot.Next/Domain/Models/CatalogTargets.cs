using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Domain.Models;

public static class CatalogTargets
{
    public const string None = "none";
    public const string Dev = "dev";
    public const string Prod = "prod";
    public const string Both = "both";

    public static string Normalize(string? value, string defaultValue = None)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return defaultValue;
        }

        return normalized switch
        {
            Dev => Dev,
            Prod => Prod,
            Both => Both,
            "all" => Both,
            "ambos" => Both,
            "producao" => Prod,
            "produção" => Prod,
            _ => None
        };
    }

    public static string ResolveConfiguredTarget(string? explicitTarget, bool legacyEnabled, string legacyDefaultTarget = Prod)
    {
        var normalized = Normalize(explicitTarget, None);
        if (!string.IsNullOrWhiteSpace(explicitTarget))
        {
            return normalized;
        }

        return legacyEnabled ? Normalize(legacyDefaultTarget, Prod) : None;
    }

    public static string ResolveDraftTarget(InstagramPublishDraft draft)
        => ResolveConfiguredTarget(draft.CatalogTarget, draft.SendToCatalog);

    public static string ResolveSettingsTarget(InstagramPublishSettings settings)
        => ResolveConfiguredTarget(settings.CatalogTarget, settings.SendToCatalog);

    public static string ResolveEffectiveTarget(InstagramPublishDraft draft, InstagramPublishSettings settings)
    {
        var draftTarget = ResolveDraftTarget(draft);
        if (!string.Equals(draftTarget, None, StringComparison.OrdinalIgnoreCase))
        {
            return draftTarget;
        }

        return ResolveSettingsTarget(settings);
    }

    public static IReadOnlyList<string> Expand(string? value, bool legacyEnabled = false, string legacyDefaultTarget = Prod)
    {
        var normalized = ResolveConfiguredTarget(value, legacyEnabled, legacyDefaultTarget);
        return normalized switch
        {
            Dev => [Dev],
            Prod => [Prod],
            Both => [Dev, Prod],
            _ => Array.Empty<string>()
        };
    }

    public static bool IsEnabled(string? value, bool legacyEnabled = false, string legacyDefaultTarget = Prod)
        => Expand(value, legacyEnabled, legacyDefaultTarget).Count > 0;
}
