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
    public TelegramToWhatsAppSettings TelegramToWhatsApp { get; set; } = new();
    public LinkResponderSettings LinkResponder { get; set; } = new();
    public InstagramPostSettings InstagramPosts { get; set; } = new();
    public InstagramPublishSettings InstagramPublish { get; set; } = new();
    public OpenAISettings OpenAI { get; set; } = new();
    public GeminiSettings Gemini { get; set; } = new();
}

public sealed class IntegrationSettings
{
    public IntegrationStatus Telegram { get; set; } = new();
    public IntegrationStatus WhatsApp { get; set; } = new();
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

public sealed class TelegramToWhatsAppSettings
{
    public bool Enabled { get; set; }
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
    public string ReplyTemplate { get; set; } = "Aqui esta o link: {link}";
    public string ReplyNoMatchTemplate { get; set; } = "Comente a palavra correta para receber o link.";
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
    public string Model { get; set; } = "gemini-2.5-flash";
    public string BaseUrl { get; set; } = "https://generativelanguage.googleapis.com/v1beta";
}
