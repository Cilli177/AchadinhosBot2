using System.Text.Json;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Tests;

public sealed class SkillHubMapperTests
{
    [Fact]
    public void BuildCatalog_ReturnsThreeSupportedTypes()
    {
        var settings = new AutomationSettings();

        var items = SkillHubMapper.BuildCatalog(settings);

        Assert.Collection(items,
            item => Assert.Equal("whatsapp_welcome", item.Type),
            item => Assert.Equal("whatsapp_invite_conversation", item.Type),
            item => Assert.Equal("converter_coupon_and_price_compare", item.Type));
    }

    [Fact]
    public void TryApplyUpdate_WelcomeSkill_MapsToExistingSettings()
    {
        var settings = new AutomationSettings();
        var request = new SkillHubUpsertRequest
        {
            Enabled = true,
            InstanceName = "ZapOfertas",
            TargetMode = "specific-chat",
            TargetChatId = "1203630@g.us",
            Templates = new Dictionary<string, List<string>>
            {
                ["welcomeTemplates"] = new() { "Bem-vindo {participant}" },
                ["followupOnYesTemplates"] = new() { "Pode contar comigo." }
            },
            Config = new Dictionary<string, JsonElement>
            {
                ["useVariableMessages"] = JsonSerializer.SerializeToElement(true),
                ["welcomeMessage"] = JsonSerializer.SerializeToElement("Mensagem fixa"),
                ["welcomeFollowupOnYesEnabled"] = JsonSerializer.SerializeToElement(true),
                ["welcomeFollowupOnYesMessage"] = JsonSerializer.SerializeToElement("Follow-up fixo")
            }
        };

        var applied = SkillHubMapper.TryApplyUpdate(settings, "whatsapp_welcome", request, out var error);

        Assert.True(applied);
        Assert.Null(error);
        Assert.True(settings.LinkResponder.WelcomeEnabled);
        Assert.Equal("ZapOfertas", settings.LinkResponder.WelcomeInstanceName);
        Assert.Equal("specific-chat", settings.LinkResponder.WelcomeTargetMode);
        Assert.Equal("1203630@g.us", settings.LinkResponder.WelcomeTargetChatId);
        Assert.Equal("Mensagem fixa", settings.LinkResponder.WelcomeMessage);
        Assert.True(settings.LinkResponder.WelcomeFollowupOnYesEnabled);
        Assert.Equal("Follow-up fixo", settings.LinkResponder.WelcomeFollowupOnYesMessage);
        Assert.True(settings.LinkResponder.WelcomeSkill.UseVariableMessages);
        Assert.Contains("Bem-vindo {participant}", settings.LinkResponder.WelcomeSkill.WelcomeTemplates);
    }

    [Fact]
    public void TryApplyUpdate_InviteSkill_MapsToExistingSettings()
    {
        var settings = new AutomationSettings();
        var request = new SkillHubUpsertRequest
        {
            Enabled = true,
            Templates = new Dictionary<string, List<string>>
            {
                ["greetingTemplates"] = new() { "Oi!" },
                ["linkAfterReplyTemplates"] = new() { "Aqui está o link." }
            },
            Config = new Dictionary<string, JsonElement>
            {
                ["useVariableMessages"] = JsonSerializer.SerializeToElement(true),
                ["minPreLinkMessages"] = JsonSerializer.SerializeToElement(2),
                ["maxPreLinkMessages"] = JsonSerializer.SerializeToElement(4)
            }
        };

        var applied = SkillHubMapper.TryApplyUpdate(settings, "whatsapp_invite_conversation", request, out var error);

        Assert.True(applied);
        Assert.Null(error);
        Assert.True(settings.WhatsAppAdminAutomation.InviteConversationSkill.Enabled);
        Assert.True(settings.WhatsAppAdminAutomation.InviteConversationSkill.UseVariableMessages);
        Assert.Equal(2, settings.WhatsAppAdminAutomation.InviteConversationSkill.MinPreLinkMessages);
        Assert.Equal(4, settings.WhatsAppAdminAutomation.InviteConversationSkill.MaxPreLinkMessages);
        Assert.Contains("Oi!", settings.WhatsAppAdminAutomation.InviteConversationSkill.GreetingTemplates);
    }

    [Fact]
    public void TryApplyUpdate_ConverterSkill_MapsToTypedSettings()
    {
        var settings = new AutomationSettings();
        var request = new SkillHubUpsertRequest
        {
            Enabled = true,
            Config = new Dictionary<string, JsonElement>
            {
                ["showOnWeb"] = JsonSerializer.SerializeToElement(true),
                ["appendToWhatsApp"] = JsonSerializer.SerializeToElement(true),
                ["storesToCompare"] = JsonSerializer.SerializeToElement(new[] { "Amazon", "Shopee" }),
                ["maxComparisonResults"] = JsonSerializer.SerializeToElement(2),
                ["requireExactProductMatch"] = JsonSerializer.SerializeToElement(true),
                ["preferOfficialData"] = JsonSerializer.SerializeToElement(true)
            }
        };

        var applied = SkillHubMapper.TryApplyUpdate(settings, "converter_coupon_and_price_compare", request, out var error);

        Assert.True(applied);
        Assert.Null(error);
        Assert.True(settings.ConverterCouponAndPriceCompareSkill.Enabled);
        Assert.True(settings.ConverterCouponAndPriceCompareSkill.ShowOnWeb);
        Assert.True(settings.ConverterCouponAndPriceCompareSkill.AppendToWhatsApp);
        Assert.Equal(2, settings.ConverterCouponAndPriceCompareSkill.MaxComparisonResults);
        Assert.Equal(new[] { "Amazon", "Shopee" }, settings.ConverterCouponAndPriceCompareSkill.StoresToCompare);
    }
}
