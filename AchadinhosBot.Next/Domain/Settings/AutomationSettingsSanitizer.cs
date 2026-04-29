using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Domain.Settings;

public static class AutomationSettingsSanitizer
{
    public static void NormalizeInPlace(AutomationSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        foreach (var rule in settings.AutoReplies)
        {
            rule.Name = Normalize(rule.Name);
            rule.Trigger = Normalize(rule.Trigger);
            rule.ResponseTemplate = Normalize(rule.ResponseTemplate);
        }

        settings.Integrations.Telegram.Notes = Normalize(settings.Integrations.Telegram.Notes);
        settings.Integrations.WhatsApp.Notes = Normalize(settings.Integrations.WhatsApp.Notes);
        settings.Integrations.MercadoLivre.Notes = Normalize(settings.Integrations.MercadoLivre.Notes);
        settings.TelegramForwarding.FooterText = Normalize(settings.TelegramForwarding.FooterText);
        settings.WhatsAppForwarding.FooterText = Normalize(settings.WhatsAppForwarding.FooterText);
        settings.LinkResponder.FooterText = Normalize(settings.LinkResponder.FooterText);
        settings.LinkResponder.ReplyTemplate = Normalize(settings.LinkResponder.ReplyTemplate);
        settings.LinkResponder.ReplyOnFailure = Normalize(settings.LinkResponder.ReplyOnFailure);
        settings.LinkResponder.WelcomeInstanceName = NormalizeNullable(settings.LinkResponder.WelcomeInstanceName);
        settings.LinkResponder.WelcomeTargetMode = Normalize(settings.LinkResponder.WelcomeTargetMode);
        settings.LinkResponder.WelcomeTargetChatId = NormalizeNullable(settings.LinkResponder.WelcomeTargetChatId);
        settings.LinkResponder.WelcomeMessage = Normalize(settings.LinkResponder.WelcomeMessage);
        settings.LinkResponder.WelcomeFollowupOnYesMessage = Normalize(settings.LinkResponder.WelcomeFollowupOnYesMessage);
        settings.LinkResponder.WelcomeSkill ??= new WhatsAppWelcomeSkillSettings();
        settings.LinkResponder.WelcomeSkill.WelcomeTemplates = NormalizeTemplateList(settings.LinkResponder.WelcomeSkill.WelcomeTemplates);
        settings.LinkResponder.WelcomeSkill.FollowupOnYesTemplates = NormalizeTemplateList(settings.LinkResponder.WelcomeSkill.FollowupOnYesTemplates);
        settings.AdminAiWorkspace ??= new AdminAiWorkspaceSettings();
        settings.AdminAiWorkspace.PinHash = Normalize(settings.AdminAiWorkspace.PinHash);
        settings.AdminAiWorkspace.CriticalConfirmationText = Normalize(settings.AdminAiWorkspace.CriticalConfirmationText);
        settings.AdminAiWorkspace.SessionDurationMinutes = Math.Clamp(settings.AdminAiWorkspace.SessionDurationMinutes, 5, 240);
        settings.AdminAiWorkspace.AllowedRoles = NormalizeRoleList(settings.AdminAiWorkspace.AllowedRoles);
        settings.AdminAiWorkspace.EnabledProviders = NormalizeProviderList(settings.AdminAiWorkspace.EnabledProviders);
        settings.ConverterCouponAndPriceCompareSkill ??= new ConverterCouponAndPriceCompareSkillSettings();
        settings.ConverterCouponAndPriceCompareSkill.StoresToCompare = NormalizeStoreList(settings.ConverterCouponAndPriceCompareSkill.StoresToCompare);
        settings.ConverterCouponAndPriceCompareSkill.MaxComparisonResults = Math.Clamp(settings.ConverterCouponAndPriceCompareSkill.MaxComparisonResults, 1, 6);
        settings.MercadoLivreAffiliateScout ??= new MercadoLivreAffiliateScoutSettings();
        settings.MercadoLivreAffiliateScout.BaseUrl = NormalizeNullable(settings.MercadoLivreAffiliateScout.BaseUrl);
        settings.MercadoLivreAffiliateScout.LoginUrl = NormalizeNullable(settings.MercadoLivreAffiliateScout.LoginUrl);
        settings.MercadoLivreAffiliateScout.HomeUrl = NormalizeNullable(settings.MercadoLivreAffiliateScout.HomeUrl);
        settings.MercadoLivreAffiliateScout.LoginUser = NormalizeNullable(settings.MercadoLivreAffiliateScout.LoginUser);
        settings.MercadoLivreAffiliateScout.LoginPassword = NormalizeNullable(settings.MercadoLivreAffiliateScout.LoginPassword);
        settings.MercadoLivreAffiliateScout.TwoFactorCode = NormalizeNullable(settings.MercadoLivreAffiliateScout.TwoFactorCode);
        settings.MercadoLivreAffiliateScout.StorageStateJson = NormalizeNullable(settings.MercadoLivreAffiliateScout.StorageStateJson);
        settings.MercadoLivreAffiliateScout.StorageStatePath = NormalizeNullable(settings.MercadoLivreAffiliateScout.StorageStatePath);
        settings.MercadoLivreAffiliateScout.AuthMode = NormalizeNullable(settings.MercadoLivreAffiliateScout.AuthMode) ?? "code-or-qr";
        settings.MercadoLivreAffiliateScout.OfferCardSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.OfferCardSelector);
        settings.MercadoLivreAffiliateScout.OfferLinkSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.OfferLinkSelector);
        settings.MercadoLivreAffiliateScout.OfferTitleSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.OfferTitleSelector);
        settings.MercadoLivreAffiliateScout.OfferPriceSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.OfferPriceSelector);
        settings.MercadoLivreAffiliateScout.OfferImageSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.OfferImageSelector);
        settings.MercadoLivreAffiliateScout.OfferCommissionSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.OfferCommissionSelector);
        settings.MercadoLivreAffiliateScout.ShareButtonSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.ShareButtonSelector);
        settings.MercadoLivreAffiliateScout.ShareActionSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.ShareActionSelector);
        settings.MercadoLivreAffiliateScout.SharedLinkSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.SharedLinkSelector);
        settings.MercadoLivreAffiliateScout.SharedLinkCopyButtonSelector = NormalizeNullable(settings.MercadoLivreAffiliateScout.SharedLinkCopyButtonSelector);
        settings.MercadoLivreAffiliateScout.WhatsAppInstanceName = NormalizeNullable(settings.MercadoLivreAffiliateScout.WhatsAppInstanceName);
        settings.MercadoLivreAffiliateScout.DestinationGroupId = NormalizeNullable(settings.MercadoLivreAffiliateScout.DestinationGroupId);
        settings.MercadoLivreAffiliateScout.ProductionRelayBaseUrl = NormalizeNullable(settings.MercadoLivreAffiliateScout.ProductionRelayBaseUrl);
        settings.MercadoLivreAffiliateScout.ProductionRelayAdminKey = NormalizeNullable(settings.MercadoLivreAffiliateScout.ProductionRelayAdminKey);
        settings.MercadoLivreAffiliateScout.ProductionRelayInstanceName = NormalizeNullable(settings.MercadoLivreAffiliateScout.ProductionRelayInstanceName);
        settings.MercadoLivreAffiliateScout.Notes = NormalizeNullable(settings.MercadoLivreAffiliateScout.Notes);
        settings.MercadoLivreAffiliateScout.IntervalMinutes = Math.Clamp(settings.MercadoLivreAffiliateScout.IntervalMinutes, 5, 240);
        settings.MercadoLivreAffiliateScout.IntervalJitterMinutes = Math.Clamp(settings.MercadoLivreAffiliateScout.IntervalJitterMinutes, 0, 30);
        settings.MercadoLivreAffiliateScout.MinCommissionPercent = Math.Clamp(settings.MercadoLivreAffiliateScout.MinCommissionPercent, 0m, 100m);
        settings.MercadoLivreAffiliateScout.Tier1MinPrice = Math.Clamp(settings.MercadoLivreAffiliateScout.Tier1MinPrice, 0m, 1000000m);
        settings.MercadoLivreAffiliateScout.Tier1MinCommissionPercent = Math.Clamp(settings.MercadoLivreAffiliateScout.Tier1MinCommissionPercent, 0m, 100m);
        settings.MercadoLivreAffiliateScout.Tier2MinPrice = Math.Clamp(settings.MercadoLivreAffiliateScout.Tier2MinPrice, 0m, 1000000m);
        settings.MercadoLivreAffiliateScout.Tier2MinCommissionPercent = Math.Clamp(settings.MercadoLivreAffiliateScout.Tier2MinCommissionPercent, 0m, 100m);
        settings.MercadoLivreAffiliateScout.Tier3MinPrice = Math.Clamp(settings.MercadoLivreAffiliateScout.Tier3MinPrice, 0m, 1000000m);
        settings.MercadoLivreAffiliateScout.Tier3MinCommissionPercent = Math.Clamp(settings.MercadoLivreAffiliateScout.Tier3MinCommissionPercent, 0m, 100m);
        settings.MercadoLivreAffiliateScout.MaxOffersPerRun = Math.Clamp(settings.MercadoLivreAffiliateScout.MaxOffersPerRun, 1, 10);
        settings.MercadoLivreAffiliateScout.RepeatWindowHours = Math.Clamp(settings.MercadoLivreAffiliateScout.RepeatWindowHours, 1, 168);
        settings.BioHub.PublicBaseUrl = NormalizePublicBaseUrl(settings.BioHub.PublicBaseUrl);
        settings.BioHub.Headline = Normalize(settings.BioHub.Headline);
        settings.BioHub.Subheadline = Normalize(settings.BioHub.Subheadline);
        settings.BioHub.ButtonLabel = Normalize(settings.BioHub.ButtonLabel);

        foreach (var route in settings.WhatsAppForwardingRoutes)
        {
            route.Name = Normalize(route.Name);
            route.FooterText = Normalize(route.FooterText);
        }

        foreach (var route in settings.TelegramToWhatsAppRoutes)
        {
            route.Name = Normalize(route.Name);
        }

        foreach (var monitored in settings.MonitoredWhatsAppGroups)
        {
            monitored.GroupId = Normalize(monitored.GroupId);
            monitored.GroupName = NormalizeNullable(monitored.GroupName);
            monitored.InstanceName = NormalizeNullable(monitored.InstanceName);
        }

        var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();

        foreach (var config in automation.InstanceParticipantAddSafety)
        {
            config.InstanceName = Normalize(config.InstanceName);
        }

        foreach (var schedule in automation.ParticipantCopySchedules)
        {
            schedule.Name = Normalize(schedule.Name);
            schedule.InstanceName = NormalizeNullable(schedule.InstanceName);
            schedule.LastResultMessage = NormalizeNullable(schedule.LastResultMessage);
        }

        foreach (var schedule in automation.ScheduledGroupMessages)
        {
            schedule.Name = Normalize(schedule.Name);
            schedule.InstanceName = NormalizeNullable(schedule.InstanceName);
            schedule.Text = Normalize(schedule.Text);
            schedule.LastResultMessage = NormalizeNullable(schedule.LastResultMessage);
        }

        foreach (var schedule in automation.ParticipantBlastSchedules)
        {
            schedule.Name = Normalize(schedule.Name);
            schedule.Status = Normalize(schedule.Status);
            schedule.InstanceName = NormalizeNullable(schedule.InstanceName);
            schedule.Message = NormalizeNullable(schedule.Message);
            schedule.LinkUrl = NormalizeNullable(schedule.LinkUrl);
            schedule.SecurityPitch = NormalizeNullable(schedule.SecurityPitch);
            schedule.WaitMode = Normalize(schedule.WaitMode);
            schedule.LastResultMessage = NormalizeNullable(schedule.LastResultMessage);
        }

        automation.InviteConversationSkill ??= new WhatsAppInviteConversationSkillSettings();
        automation.InviteConversationSkill.MinPreLinkMessages = Math.Clamp(automation.InviteConversationSkill.MinPreLinkMessages, 2, 4);
        automation.InviteConversationSkill.MaxPreLinkMessages = Math.Clamp(automation.InviteConversationSkill.MaxPreLinkMessages, automation.InviteConversationSkill.MinPreLinkMessages, 4);
        automation.InviteConversationSkill.GreetingTemplates = NormalizeTemplateList(automation.InviteConversationSkill.GreetingTemplates);
        automation.InviteConversationSkill.ExplainTemplates = NormalizeTemplateList(automation.InviteConversationSkill.ExplainTemplates);
        automation.InviteConversationSkill.TrustTemplates = NormalizeTemplateList(automation.InviteConversationSkill.TrustTemplates);
        automation.InviteConversationSkill.AskTemplates = NormalizeTemplateList(automation.InviteConversationSkill.AskTemplates);
        automation.InviteConversationSkill.LinkAfterReplyTemplates = NormalizeTemplateList(automation.InviteConversationSkill.LinkAfterReplyTemplates);
        automation.InviteConversationSkill.LinkAfterTimeoutTemplates = NormalizeTemplateList(automation.InviteConversationSkill.LinkAfterTimeoutTemplates);
    }

    public static string Normalize(string? value)
    {
        var normalized = NormalizeNullable(value);
        return string.IsNullOrWhiteSpace(normalized) ? string.Empty : normalized;
    }

    public static string? NormalizeNullable(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var normalized = value.Replace("\r\n", "\n").Replace('\r', '\n').Trim();

        for (var i = 0; i < 2 && LooksBroken(normalized); i++)
        {
            normalized = TryRepairEncoding(normalized);
        }

        foreach (var replacement in Replacements)
        {
            normalized = normalized.Replace(replacement.Key, replacement.Value, StringComparison.Ordinal);
        }

        normalized = Regex.Replace(normalized, @"[ \t]+\n", "\n", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"\n{3,}", "\n\n", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"[ \t]{2,}", " ", RegexOptions.CultureInvariant);
        normalized = WhatsAppInviteLinkNormalizer.NormalizeOfficialFooterLinks(normalized);

        return normalized.Trim();
    }

    private static List<string> NormalizeTemplateList(List<string>? values)
    {
        if (values is null || values.Count == 0)
        {
            return new List<string>();
        }

        return values
            .Select(NormalizeNullable)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private static List<string> NormalizeStoreList(List<string>? values)
    {
        if (values is null || values.Count == 0)
        {
            return new List<string> { "Amazon", "Mercado Livre", "Shopee", "Shein" };
        }

        var normalized = values
            .Select(NormalizeNullable)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return normalized.Count > 0
            ? normalized
            : new List<string> { "Amazon", "Mercado Livre", "Shopee", "Shein" };
    }

    private static List<string> NormalizeRoleList(List<string>? values)
    {
        var defaults = new List<string> { "admin" };
        if (values is null || values.Count == 0)
        {
            return defaults;
        }

        var normalized = values
            .Select(NormalizeNullable)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!.Trim().ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return normalized.Count > 0 ? normalized : defaults;
    }

    private static List<string> NormalizeProviderList(List<string>? values)
    {
        var defaults = new List<string> { "codex", "vscode", "antigravity" };
        if (values is null || values.Count == 0)
        {
            return defaults;
        }

        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "codex",
            "vscode",
            "antigravity"
        };

        var normalized = values
            .Select(NormalizeNullable)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!.Trim().ToLowerInvariant())
            .Where(x => allowed.Contains(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return normalized.Count > 0 ? normalized : defaults;
    }

    private static bool LooksBroken(string text)
        => text.Contains('\uFFFD') ||
           text.Contains("Ã", StringComparison.Ordinal) ||
           text.Contains("ðŸ", StringComparison.Ordinal) ||
           text.Contains("â", StringComparison.Ordinal) ||
           text.Contains("??", StringComparison.Ordinal) ||
           text.Contains("?o", StringComparison.Ordinal) ||
           text.Contains("C????", StringComparison.Ordinal);

    private static string TryRepairEncoding(string text)
    {
        try
        {
            var bytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(text);
            var repaired = Encoding.UTF8.GetString(bytes);
            if (!string.IsNullOrWhiteSpace(repaired) && repaired != text)
            {
                text = repaired;
            }
        }
        catch
        {
        }

        return text.Replace("\uFFFD", string.Empty, StringComparison.Ordinal);
    }

    private static readonly IReadOnlyDictionary<string, string> Replacements = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["Ol?! Manda seu link que eu converto para afiliado ??"] = "Ol\u00E1! Manda seu link que eu converto para afiliado.",
        ["Ol\u00E1! Manda seu link que eu converto para afiliado ??"] = "Ol\u00E1! Manda seu link que eu converto para afiliado.",
        ["Ol\u00C3\u00A1! Manda seu link que eu converto para afiliado \u00F0\u0178\u0161\u20AC"] = "Ol\u00E1! Manda seu link que eu converto para afiliado.",
        ["?? Acesse o link: bio.reidasofertas.ia.br"] = "Acesse o link: https://bio.reidasofertas.ia.br",
        ["?? Para mais novidades acesse: bio.reidasofertas.ia.br"] = "Para mais novidades, acesse: https://bio.reidasofertas.ia.br",
        ["YZAcesse o link: bio.reidasofertas.ia.br"] = "Acesse o link: https://bio.reidasofertas.ia.br",
        ["YZPara mais novidades, acesse: bio.reidasofertas.ia.br"] = "Para mais novidades, acesse: https://bio.reidasofertas.ia.br",
        ["??Segue seu Link convertido:"] = "Segue seu link convertido:",
        ["C????pia "] = "C\u00F3pia ",
        ["Para n?o perder as ofertas e evitar excesso de notifica??es, deixe este grupo silenciado.\n\nNo WhatsApp: abra o grupo -> toque no nome -> Silenciar notifica??es -> Sempre.\n\nEnquanto isso, acompanhe o conversor aqui:\nhttps://reidasofertas.ia.br/conversor"] =
            "Para n\u00E3o perder as ofertas e evitar excesso de notifica\u00E7\u00F5es, deixe este grupo silenciado.\n\nNo WhatsApp: abra o grupo -> toque no nome -> Silenciar notifica\u00E7\u00F5es -> Sempre.\n\nEnquanto isso, acompanhe o conversor aqui:\nhttps://reidasofertas.ia.br/conversor",
        ["n?o"] = "n\u00E3o",
        ["N?o"] = "N\u00E3o",
        ["notifica??es"] = "notifica\u00E7\u00F5es",
        ["Notifica??es"] = "Notifica\u00E7\u00F5es",
        ["adiÃ§Ãµes"] = "adi\u00E7\u00F5es",
        ["adiÃƒÂ§ÃƒÂµes"] = "adi\u00E7\u00F5es",
        ["prÃ³xima"] = "pr\u00F3xima",
        ["prÃƒÂ³xima"] = "pr\u00F3xima",
        ["CÃ³pia"] = "C\u00F3pia",
        ["CÃƒÂ³pia"] = "C\u00F3pia",
        ["ConcluÃ­do"] = "Conclu\u00EDdo",
        ["estÃ¡"] = "est\u00E1",
        ["estÃƒÂ¡"] = "est\u00E1",
        ["nÃ£o"] = "n\u00E3o",
        ["nÃƒÂ£o"] = "n\u00E3o",
        ["NÃ£o"] = "N\u00E3o",
        ["NÃƒÂ£o"] = "N\u00E3o",
        ["ConfiguraÃ§Ãµes"] = "Configura\u00E7\u00F5es",
        ["ConfiguraÃƒÂ§ÃƒÂµes"] = "Configura\u00E7\u00F5es",
        ["OlÃ¡"] = "Ol\u00E1",
        ["OlÃƒÂ¡"] = "Ol\u00E1",
        ["botÃ£o"] = "bot\u00E3o",
        ["botÃƒÂ£o"] = "bot\u00E3o",
        ["aÃ§Ãµes"] = "a\u00E7\u00F5es",
        ["aÃƒÂ§ÃƒÂµes"] = "a\u00E7\u00F5es",
        ["LanÃ§ando"] = "Lan\u00E7ando",
        ["LanÃƒÂ§ando"] = "Lan\u00E7ando",
        ["deduplicaÃ§Ã£o"] = "deduplica\u00E7\u00E3o",
        ["apÃ³s"] = "ap\u00F3s",
        ["diÃ¡rio"] = "di\u00E1rio",
        ["silenciado.\n\nNo WhatsApp: abra o grupo -> toque no nome -> Silenciar notifica??es -> Sempre."] =
            "silenciado.\n\nNo WhatsApp: abra o grupo -> toque no nome -> Silenciar notifica\u00E7\u00F5es -> Sempre."
    };

    private static string NormalizePublicBaseUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri))
        {
            return Normalize(value);
        }

        return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
    }
}
