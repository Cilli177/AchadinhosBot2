namespace AchadinhosBot.Next.Domain.Settings;

public sealed class AutomationSettings
{
    public IntegrationSettings Integrations { get; set; } = new();
    public List<AutoReplyRule> AutoReplies { get; set; } =
    [
        new AutoReplyRule
        {
            Id = Guid.NewGuid(),
            Name = "Boas-vindas",
            Trigger = "oi",
            ResponseTemplate = "Olá! Manda seu link que eu converto para afiliado 🚀",
            Enabled = true
        }
    ];

    public LinkAutomationSettings LinkAutomation { get; set; } = new();
    public AutoReplySettings AutoRepliesSettings { get; set; } = new();
    public TelegramForwardingSettings TelegramForwarding { get; set; } = new();
    public WhatsAppForwardingSettings WhatsAppForwarding { get; set; } = new();
    public List<WhatsAppForwardingRouteSettings> WhatsAppForwardingRoutes { get; set; } = new();
    public TelegramToWhatsAppSettings TelegramToWhatsApp { get; set; } = new();
    public List<TelegramToWhatsAppRouteSettings> TelegramToWhatsAppRoutes { get; set; } = new();
    public LinkResponderSettings LinkResponder { get; set; } = new();
    public BioHubSettings BioHub { get; set; } = new();
    public MercadoLivreComplianceSettings MercadoLivreCompliance { get; set; } = new();
    public LinkIntegritySettings LinkIntegrity { get; set; } = new();
    public CouponHubSettings CouponHub { get; set; } = new();
    public ContentCalendarSettings ContentCalendar { get; set; } = new();
    public InstagramPostSettings InstagramPosts { get; set; } = new();
    public InstagramPublishSettings InstagramPublish { get; set; } = new();
    public OpenAISettings OpenAI { get; set; } = new();
    public GeminiSettings Gemini { get; set; } = new();
}

public sealed class IntegrationSettings
{
    public IntegrationStatus Telegram { get; set; } = new();
    public IntegrationStatus WhatsApp { get; set; } = new();
    public IntegrationStatus MercadoLivre { get; set; } = new();
}

public sealed class IntegrationStatus
{
    public bool Connected { get; set; }
    public string? Identifier { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    public string Notes { get; set; } = "Não conectado";
}

public sealed class AutoReplyRule
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Trigger { get; set; } = string.Empty;
    public string ResponseTemplate { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}

public sealed class AutoReplySettings
{
    public bool Enabled { get; set; } = true;
}

public sealed class LinkAutomationSettings
{
    public bool AutoConvertIncomingLinks { get; set; } = true;
    public bool AutoSendToDestinationChannel { get; set; } = false;
    public string DestinationChannel { get; set; } = "@seuCanal";
}

public sealed class TelegramForwardingSettings
{
    public bool Enabled { get; set; }
    public long DestinationChatId { get; set; }
    public List<long> SourceChatIds { get; set; } = new();
    public bool AppendSheinCode { get; set; } = true;
    public string FooterText { get; set; } = "🔥 Vi no: @ReiDasOfertasVIP";
}

public sealed class WhatsAppForwardingSettings
{
    public bool Enabled { get; set; }
    public bool ProcessFromMeOnly { get; set; } = true;
    public List<string> SourceChatIds { get; set; } = new();
    public List<string> DestinationGroupIds { get; set; } = new();
    public bool AppendSheinCode { get; set; } = true;
    public bool SendMediaEnabled { get; set; } = true;
    public string FooterText { get; set; } = string.Empty;
    public string? InstanceName { get; set; }
}

public sealed class WhatsAppForwardingRouteSettings
{
    public string Name { get; set; } = "Rota WhatsApp";
    public bool Enabled { get; set; } = true;
    public bool ProcessFromMeOnly { get; set; } = true;
    public List<string> SourceChatIds { get; set; } = new();
    public List<string> DestinationGroupIds { get; set; } = new();
    public bool AppendSheinCode { get; set; } = true;
    public bool SendMediaEnabled { get; set; } = true;
    public string FooterText { get; set; } = string.Empty;
    public string? InstanceName { get; set; }
}

public sealed class TelegramToWhatsAppSettings
{
    public bool Enabled { get; set; }
    public List<long> SourceChatIds { get; set; } = new();
    public List<string> DestinationGroupIds { get; set; } = new();
}

public sealed class TelegramToWhatsAppRouteSettings
{
    public string Name { get; set; } = "Rota Telegram -> WhatsApp";
    public bool Enabled { get; set; } = true;
    public List<long> SourceChatIds { get; set; } = new();
    public List<string> DestinationGroupIds { get; set; } = new();
}

public sealed class LinkResponderSettings
{
    public bool Enabled { get; set; }
    public bool AllowWhatsApp { get; set; } = true;
    public bool AllowTelegramBot { get; set; }
    public bool AllowTelegramUserbot { get; set; }
    public bool TrackingEnabled { get; set; } = true;
    public bool WhatsAppAllowPrivate { get; set; } = true;
    public bool WhatsAppAllowGroups { get; set; }
    public List<string> WhatsAppChatIds { get; set; } = new();
    public bool TelegramAllowPrivate { get; set; } = true;
    public bool TelegramAllowGroups { get; set; }
    public List<long> TelegramChatIds { get; set; } = new();
    public bool AppendSheinCode { get; set; } = true;
    public string FooterText { get; set; } = string.Empty;
    public string ReplyTemplate { get; set; } = "Link convertido:\n{link}";
    public string ReplyOnFailure { get; set; } = "Link não suportado.";
}

public sealed class BioHubSettings
{
    public bool Enabled { get; set; } = true;
    public string PublicBaseUrl { get; set; } = string.Empty;
    public string BrandName { get; set; } = "Rei das Ofertas";
    public string Headline { get; set; } = "Achadinhos em destaque";
    public string Subheadline { get; set; } = "Toque no botão para abrir a oferta com o melhor link.";
    public string ButtonLabel { get; set; } = "Abrir oferta";
    public int MaxItems { get; set; } = 40;
    public string DefaultSource { get; set; } = "bio";
    public string DefaultCampaign { get; set; } = string.Empty;
}

public sealed class MercadoLivreComplianceSettings
{
    public bool Enabled { get; set; }
    public bool BlockAutoFlows { get; set; } = true;
    public bool RequireManualApproval { get; set; } = true;
    public bool EnforceChannelWhitelist { get; set; }
    public bool BlockWhenChannelUnknown { get; set; } = true;
    public List<string> AllowedChannels { get; set; } = new();
}

public sealed class LinkIntegritySettings
{
    public bool Enabled { get; set; } = true;
    public bool BlockAutomaticFlowOnNonAffiliated { get; set; } = true;
    public bool BlockAutomaticFlowOnConversionFailure { get; set; } = true;
    public bool IgnoreUnknownStores { get; set; } = true;
    public List<string> EnforcedStores { get; set; } = ["Amazon", "Shopee", "Shein", "Mercado Livre"];
}

public sealed class CouponHubSettings
{
    public bool Enabled { get; set; } = true;
    public bool AppendToConvertedMessages { get; set; } = true;
    public bool AppendToInstagramCaptions { get; set; } = true;
    public int MaxCouponsPerStore { get; set; } = 1;
    public List<AffiliateCoupon> Coupons { get; set; } = new();
}

public sealed class ContentCalendarSettings
{
    public bool Enabled { get; set; } = true;
    public int PollIntervalSeconds { get; set; } = 60;
    public int MaxAttempts { get; set; } = 3;
}

public sealed class AffiliateCoupon
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public bool Enabled { get; set; } = true;
    public string Store { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? AffiliateLink { get; set; }
    public DateTimeOffset? StartsAt { get; set; }
    public DateTimeOffset? EndsAt { get; set; }
    public int Priority { get; set; } = 100;
    public string Source { get; set; } = "manual";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class InstagramPostSettings
{
    public bool Enabled { get; set; } = true;
    public List<string> Triggers { get; set; } = ["criar postagem", "postar", "insta"];
    public bool AllowWhatsApp { get; set; } = true;
    public bool AllowTelegramBot { get; set; }
    public bool AllowTelegramUserbot { get; set; }
    public bool WhatsAppAllowPrivate { get; set; } = true;
    public bool WhatsAppAllowGroups { get; set; } = false;
    public List<string> WhatsAppChatIds { get; set; } = new();
    public bool TelegramAllowPrivate { get; set; } = true;
    public bool TelegramAllowGroups { get; set; } = true;
    public List<long> TelegramChatIds { get; set; } = new();
    public InstagramOfferContextMode OfferContextMode { get; set; } = InstagramOfferContextMode.Off;
    public bool UseOfferContext { get; set; }
    public bool UseAi { get; set; }
    public int VariationsCount { get; set; } = 2;
    public string AiProvider { get; set; } = "openai";
    public bool UseUltraPrompt { get; set; }
    public bool UseShortProductName { get; set; }
    public bool UseBenefitBullets { get; set; }
    public bool UseAbSuggestion { get; set; } = true;
    public bool UseImageDownload { get; set; }
    public List<string> CaptionTemplates { get; set; } =
    [
        "Oferta em destaque: {title}\n\n{lead}\n\nComente \"{keyword}\" para receber o link.\n\n{hashtags}",
        "Oferta: {title}\n\nPontos principais:\n- {bullet1}\n- {bullet2}\n- {bullet3}\n\nComente \"{keyword}\" para receber o link.\n\n{hashtags}",
        "Oferta do dia: {title}\n\n{short}\n\nComente \"{keyword}\" para receber o link.\n\n{hashtags}"
    ];
    public string NichePreset { get; set; } = "geral";
    public string PromptPreset { get; set; } = "premium";
    public string PromptTemplate { get; set; } =
        "Voce e um copywriter profissional de afiliados no Brasil.\n" +
        "Crie um post para Instagram objetivo, persuasivo e com linguagem natural.\n" +
        "Nao invente preco ou beneficios nao informados.\n\n" +
        "{{format}}\n\n" +
        "Dados:\n" +
        "Entrada: {{input}}\n" +
        "Link afiliado: {{link}}\n" +
        "Contexto da oferta: {{context}}\n\n" +
        "Rodape (se houver): {{footer}}\n";
    public string FooterText { get; set; } = string.Empty;
}

public sealed class InstagramPublishSettings
{
    public bool Enabled { get; set; } = true;
    public string GraphBaseUrl { get; set; } = "https://graph.facebook.com/v19.0";
    public string? AccessToken { get; set; }
    public string? InstagramUserId { get; set; }
    public string? VerifyToken { get; set; }
    public bool AutoReplyEnabled { get; set; } = true;
    public bool AutoReplyOnlyOnKeywordMatch { get; set; } = true;
    public string ReplyTemplate { get; set; } = "Aqui esta o link: {link}";
    public string ReplyNoMatchTemplate { get; set; } = "Comente a palavra correta para receber o link.";
    public bool AutoDmEnabled { get; set; }
    public string DmProvider { get; set; } = "meta";
    public bool DmFallbackToManyChatOnError { get; set; } = true;
    public string DmTemplate { get; set; } = "Oi {name}! Aqui esta seu link: {link}";
    public string? ManyChatWebhookUrl { get; set; }
    public string? ManyChatApiKey { get; set; }
    public bool AutoPilotEnabled { get; set; }
    public int AutoPilotIntervalMinutes { get; set; } = 180;
    public int AutoPilotTopCount { get; set; } = 3;
    public int AutoPilotLookbackHours { get; set; } = 24;
    public int AutoPilotRepeatWindowHours { get; set; } = 48;
    public bool AutoPilotAllowShortLinks { get; set; }
    public int AutoPilotWeightSales { get; set; } = 35;
    public int AutoPilotWeightReturn { get; set; } = 30;
    public int AutoPilotWeightDiscount { get; set; } = 25;
    public int AutoPilotWeightRecency { get; set; } = 10;
    public bool AutoPilotRequireOfficialProductData { get; set; } = true;
    public int AutoPilotMinimumImageMatchScore { get; set; } = 80;
    public bool AutoPilotRequireAiCaption { get; set; } = true;
    public bool AutoPilotSendForApproval { get; set; } = true;
    public string AutoPilotApprovalChannel { get; set; } = "telegram";
    public long AutoPilotApprovalTelegramChatId { get; set; }
    public string? AutoPilotApprovalWhatsAppGroupId { get; set; }
    public string? AutoPilotApprovalWhatsAppInstanceName { get; set; }
    public bool StoryAutoPilotEnabled { get; set; }
    public int StoryAutoPilotIntervalMinutes { get; set; } = 240;
    public int StoryAutoPilotTopCount { get; set; } = 2;
    public int StoryAutoPilotLookbackHours { get; set; } = 24;
    public int StoryAutoPilotRepeatWindowHours { get; set; } = 24;
    public bool StoryAutoPilotSendForApproval { get; set; } = true;
    public string StoryAutoPilotApprovalChannel { get; set; } = "whatsapp";
    public long StoryAutoPilotApprovalTelegramChatId { get; set; }
    public string? StoryAutoPilotApprovalWhatsAppGroupId { get; set; }
    public string? StoryAutoPilotApprovalWhatsAppInstanceName { get; set; }
}

public enum InstagramOfferContextMode
{
    Off,
    Suggestion,
    ExtraPost
}

public sealed class OpenAISettings
{
    public string? ApiKey { get; set; }
    public string Model { get; set; } = "gpt-4o-mini";
    public double Temperature { get; set; } = 0.7;
    public int MaxOutputTokens { get; set; } = 700;
    public string BaseUrl { get; set; } = "https://api.openai.com/v1";
}

public sealed class GeminiSettings
{
    public string? ApiKey { get; set; }
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "gemini-2.5-flash";
    public string BaseUrl { get; set; } = "https://generativelanguage.googleapis.com/v1beta";
    public int MaxOutputTokens { get; set; } = 1200;
}
