using System.Text.Json;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Services;

public static class SkillHubMapper
{
    public static IReadOnlyList<SkillHubItemDto> BuildCatalog(AutomationSettings settings)
        => new[]
        {
            BuildWelcome(settings),
            BuildInvite(settings),
            BuildConverter(settings)
        };

    public static SkillHubItemDto? BuildSkill(AutomationSettings settings, string type)
        => NormalizeType(type) switch
        {
            "whatsapp_welcome" => BuildWelcome(settings),
            "whatsapp_invite_conversation" => BuildInvite(settings),
            "converter_coupon_and_price_compare" => BuildConverter(settings),
            _ => null
        };

    public static bool TryApplyUpdate(
        AutomationSettings settings,
        string type,
        SkillHubUpsertRequest request,
        out string? error)
    {
        error = null;
        switch (NormalizeType(type))
        {
            case "whatsapp_welcome":
                ApplyWelcome(settings, request);
                return true;
            case "whatsapp_invite_conversation":
                ApplyInvite(settings, request);
                return true;
            case "converter_coupon_and_price_compare":
                ApplyConverter(settings, request);
                return true;
            default:
                error = "Tipo de skill nao suportado.";
                return false;
        }
    }

    private static SkillHubItemDto BuildWelcome(AutomationSettings settings)
    {
        var responder = settings.LinkResponder ?? new LinkResponderSettings();
        var skill = responder.WelcomeSkill ?? new WhatsAppWelcomeSkillSettings();
        return new SkillHubItemDto
        {
            Type = "whatsapp_welcome",
            DisplayName = "WhatsApp Welcome",
            Channel = "whatsapp",
            Enabled = responder.WelcomeEnabled && skill.Enabled,
            InstanceName = responder.WelcomeInstanceName,
            TargetMode = responder.WelcomeTargetMode,
            TargetChatId = responder.WelcomeTargetChatId,
            Templates = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["welcomeTemplates"] = skill.WelcomeTemplates?.ToList() ?? new List<string>(),
                ["followupOnYesTemplates"] = skill.FollowupOnYesTemplates?.ToList() ?? new List<string>()
            },
            Config = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["useVariableMessages"] = skill.UseVariableMessages,
                ["welcomeMessage"] = responder.WelcomeMessage,
                ["welcomeFollowupOnYesEnabled"] = responder.WelcomeFollowupOnYesEnabled,
                ["welcomeFollowupOnYesMessage"] = responder.WelcomeFollowupOnYesMessage
            }
        };
    }

    private static SkillHubItemDto BuildInvite(AutomationSettings settings)
    {
        var automation = settings.WhatsAppAdminAutomation ?? new WhatsAppAdminAutomationSettings();
        var skill = automation.InviteConversationSkill ?? new WhatsAppInviteConversationSkillSettings();
        return new SkillHubItemDto
        {
            Type = "whatsapp_invite_conversation",
            DisplayName = "WhatsApp Invite Conversation",
            Channel = "whatsapp",
            Enabled = skill.Enabled,
            Templates = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["greetingTemplates"] = skill.GreetingTemplates?.ToList() ?? new List<string>(),
                ["explainTemplates"] = skill.ExplainTemplates?.ToList() ?? new List<string>(),
                ["trustTemplates"] = skill.TrustTemplates?.ToList() ?? new List<string>(),
                ["askTemplates"] = skill.AskTemplates?.ToList() ?? new List<string>(),
                ["linkAfterReplyTemplates"] = skill.LinkAfterReplyTemplates?.ToList() ?? new List<string>(),
                ["linkAfterTimeoutTemplates"] = skill.LinkAfterTimeoutTemplates?.ToList() ?? new List<string>()
            },
            Config = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["useVariableMessages"] = skill.UseVariableMessages,
                ["minPreLinkMessages"] = skill.MinPreLinkMessages,
                ["maxPreLinkMessages"] = skill.MaxPreLinkMessages
            }
        };
    }

    private static SkillHubItemDto BuildConverter(AutomationSettings settings)
    {
        var skill = settings.ConverterCouponAndPriceCompareSkill ?? new ConverterCouponAndPriceCompareSkillSettings();
        return new SkillHubItemDto
        {
            Type = "converter_coupon_and_price_compare",
            DisplayName = "Conversor Coupon + Price Compare",
            Channel = "converter",
            Enabled = skill.Enabled,
            Templates = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase),
            Config = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["showOnWeb"] = skill.ShowOnWeb,
                ["appendToWhatsApp"] = skill.AppendToWhatsApp,
                ["storesToCompare"] = skill.StoresToCompare?.ToList() ?? new List<string>(),
                ["maxComparisonResults"] = skill.MaxComparisonResults,
                ["requireExactProductMatch"] = skill.RequireExactProductMatch,
                ["preferOfficialData"] = skill.PreferOfficialData
            }
        };
    }

    private static void ApplyWelcome(AutomationSettings settings, SkillHubUpsertRequest request)
    {
        var responder = settings.LinkResponder ??= new LinkResponderSettings();
        var skill = responder.WelcomeSkill ??= new WhatsAppWelcomeSkillSettings();

        if (request.Enabled.HasValue)
        {
            responder.WelcomeEnabled = request.Enabled.Value;
            skill.Enabled = request.Enabled.Value;
        }

        if (request.InstanceName is not null)
        {
            responder.WelcomeInstanceName = NormalizeNullable(request.InstanceName);
        }

        if (request.TargetMode is not null)
        {
            responder.WelcomeTargetMode = NormalizeNullable(request.TargetMode) ?? "private";
        }

        if (request.TargetChatId is not null)
        {
            responder.WelcomeTargetChatId = NormalizeNullable(request.TargetChatId);
        }

        ApplyTemplateList(request, "welcomeTemplates", x => skill.WelcomeTemplates = x);
        ApplyTemplateList(request, "followupOnYesTemplates", x => skill.FollowupOnYesTemplates = x);

        if (TryGetConfigBool(request, "useVariableMessages", out var useVariableMessages))
        {
            skill.UseVariableMessages = useVariableMessages;
        }

        if (TryGetConfigString(request, "welcomeMessage", out var welcomeMessage))
        {
            responder.WelcomeMessage = welcomeMessage;
        }

        if (TryGetConfigBool(request, "welcomeFollowupOnYesEnabled", out var followupEnabled))
        {
            responder.WelcomeFollowupOnYesEnabled = followupEnabled;
        }

        if (TryGetConfigString(request, "welcomeFollowupOnYesMessage", out var followupMessage))
        {
            responder.WelcomeFollowupOnYesMessage = followupMessage;
        }
    }

    private static void ApplyInvite(AutomationSettings settings, SkillHubUpsertRequest request)
    {
        var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
        var skill = automation.InviteConversationSkill ??= new WhatsAppInviteConversationSkillSettings();

        if (request.Enabled.HasValue)
        {
            skill.Enabled = request.Enabled.Value;
        }

        ApplyTemplateList(request, "greetingTemplates", x => skill.GreetingTemplates = x);
        ApplyTemplateList(request, "explainTemplates", x => skill.ExplainTemplates = x);
        ApplyTemplateList(request, "trustTemplates", x => skill.TrustTemplates = x);
        ApplyTemplateList(request, "askTemplates", x => skill.AskTemplates = x);
        ApplyTemplateList(request, "linkAfterReplyTemplates", x => skill.LinkAfterReplyTemplates = x);
        ApplyTemplateList(request, "linkAfterTimeoutTemplates", x => skill.LinkAfterTimeoutTemplates = x);

        if (TryGetConfigBool(request, "useVariableMessages", out var useVariableMessages))
        {
            skill.UseVariableMessages = useVariableMessages;
        }

        if (TryGetConfigInt(request, "minPreLinkMessages", out var minPreLinkMessages))
        {
            skill.MinPreLinkMessages = Math.Clamp(minPreLinkMessages, 2, 4);
        }

        if (TryGetConfigInt(request, "maxPreLinkMessages", out var maxPreLinkMessages))
        {
            skill.MaxPreLinkMessages = Math.Clamp(maxPreLinkMessages, skill.MinPreLinkMessages, 4);
        }
    }

    private static void ApplyConverter(AutomationSettings settings, SkillHubUpsertRequest request)
    {
        var skill = settings.ConverterCouponAndPriceCompareSkill ??= new ConverterCouponAndPriceCompareSkillSettings();

        if (request.Enabled.HasValue)
        {
            skill.Enabled = request.Enabled.Value;
        }

        if (TryGetConfigBool(request, "showOnWeb", out var showOnWeb))
        {
            skill.ShowOnWeb = showOnWeb;
        }

        if (TryGetConfigBool(request, "appendToWhatsApp", out var appendToWhatsApp))
        {
            skill.AppendToWhatsApp = appendToWhatsApp;
        }

        if (TryGetConfigStringList(request, "storesToCompare", out var storesToCompare))
        {
            skill.StoresToCompare = storesToCompare;
        }

        if (TryGetConfigInt(request, "maxComparisonResults", out var maxComparisonResults))
        {
            skill.MaxComparisonResults = Math.Clamp(maxComparisonResults, 1, 6);
        }

        if (TryGetConfigBool(request, "requireExactProductMatch", out var requireExactProductMatch))
        {
            skill.RequireExactProductMatch = requireExactProductMatch;
        }

        if (TryGetConfigBool(request, "preferOfficialData", out var preferOfficialData))
        {
            skill.PreferOfficialData = preferOfficialData;
        }
    }

    private static void ApplyTemplateList(SkillHubUpsertRequest request, string key, Action<List<string>> setter)
    {
        if (request.Templates is null || !request.Templates.TryGetValue(key, out var values))
        {
            return;
        }

        setter(values
            .Select(NormalizeNullable)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList());
    }

    private static bool TryGetConfigBool(SkillHubUpsertRequest request, string key, out bool value)
    {
        value = false;
        if (request.Config is null || !request.Config.TryGetValue(key, out var raw))
        {
            return false;
        }

        if (raw.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            value = raw.GetBoolean();
            return true;
        }

        if (raw.ValueKind == JsonValueKind.String && bool.TryParse(raw.GetString(), out var parsed))
        {
            value = parsed;
            return true;
        }

        return false;
    }

    private static bool TryGetConfigInt(SkillHubUpsertRequest request, string key, out int value)
    {
        value = 0;
        if (request.Config is null || !request.Config.TryGetValue(key, out var raw))
        {
            return false;
        }

        if (raw.ValueKind == JsonValueKind.Number && raw.TryGetInt32(out var parsed))
        {
            value = parsed;
            return true;
        }

        if (raw.ValueKind == JsonValueKind.String && int.TryParse(raw.GetString(), out parsed))
        {
            value = parsed;
            return true;
        }

        return false;
    }

    private static bool TryGetConfigString(SkillHubUpsertRequest request, string key, out string value)
    {
        value = string.Empty;
        if (request.Config is null || !request.Config.TryGetValue(key, out var raw))
        {
            return false;
        }

        if (raw.ValueKind == JsonValueKind.String)
        {
            value = raw.GetString()?.Trim() ?? string.Empty;
            return true;
        }

        return false;
    }

    private static bool TryGetConfigStringList(SkillHubUpsertRequest request, string key, out List<string> values)
    {
        values = new List<string>();
        if (request.Config is null || !request.Config.TryGetValue(key, out var raw) || raw.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        values = raw.EnumerateArray()
            .Where(x => x.ValueKind == JsonValueKind.String)
            .Select(x => NormalizeNullable(x.GetString()))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        return true;
    }

    private static string NormalizeType(string? type)
        => string.IsNullOrWhiteSpace(type) ? string.Empty : type.Trim().ToLowerInvariant();

    private static string? NormalizeNullable(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed class SkillHubItemDto
{
    public string Type { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Channel { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string? InstanceName { get; set; }
    public string? TargetMode { get; set; }
    public string? TargetChatId { get; set; }
    public Dictionary<string, List<string>> Templates { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, object?> Config { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class SkillHubUpsertRequest
{
    public bool? Enabled { get; set; }
    public string? InstanceName { get; set; }
    public string? TargetMode { get; set; }
    public string? TargetChatId { get; set; }
    public Dictionary<string, List<string>>? Templates { get; set; }
    public Dictionary<string, JsonElement>? Config { get; set; }
}
