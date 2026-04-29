using AchadinhosBot.Next.Domain.Models;

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
            ResponseTemplate = "Ol\u00E1! Manda seu link que eu converto para afiliado.",
            Enabled = false
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
    public Gemma4Settings Gemma4 { get; set; } = new();
    public DeepSeekSettings DeepSeek { get; set; } = new();
    public NemotronSettings Nemotron { get; set; } = new();
    public QwenSettings Qwen { get; set; } = new();
    public VilaNvidiaSettings VilaNvidia { get; set; } = new();
    public AdminAiWorkspaceSettings AdminAiWorkspace { get; set; } = new();
    public List<string> MonitoredGroupIds { get; set; } = new();
    public List<WhatsAppMonitoredGroup> MonitoredWhatsAppGroups { get; set; } = new();
    public WhatsAppAdminAutomationSettings WhatsAppAdminAutomation { get; set; } = new();
    public ConverterCouponAndPriceCompareSkillSettings ConverterCouponAndPriceCompareSkill { get; set; } = new();
    public WhatsAppAiAgentSettings WhatsAppAiAgent { get; set; } = new();
    public AmazonPlaywrightScraperSettings AmazonPlaywrightScraper { get; set; } = new();
    public MercadoLivreAffiliateScoutSettings MercadoLivreAffiliateScout { get; set; } = new();
}

public sealed class AdminAiWorkspaceSettings
{
    public bool Enabled { get; set; } = true;
    public List<string> AllowedRoles { get; set; } = new() { "admin" };
    public string PinHash { get; set; } = string.Empty;
    public int SessionDurationMinutes { get; set; } = 45;
    public bool AllowTerminal { get; set; } = true;
    public bool AllowAdminTerminal { get; set; } = true;
    public bool AllowWorkspaceWrite { get; set; } = true;
    public bool AllowProdOperations { get; set; } = false;
    public List<string> EnabledProviders { get; set; } = new() { "codex", "vscode", "antigravity" };
    public bool AuditEnabled { get; set; } = true;
    public string CriticalConfirmationText { get; set; } = "CONFIRMAR-PROD";
}

public sealed class WhatsAppMonitoredGroup
{
    public string GroupId { get; set; } = string.Empty;
    public string? GroupName { get; set; }
    public string? InstanceName { get; set; }
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
    public string Notes { get; set; } = "N\u00E3o conectado";
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
    public bool Enabled { get; set; } = false;
}

public sealed class LinkAutomationSettings
{
    public bool AutoConvertIncomingLinks { get; set; } = true;
    public bool AutoSendToDestinationChannel { get; set; } = false;
    public string DestinationChannel { get; set; } = "@seuCanal";
    public bool EnableExternalShortener { get; set; } = false;
    public string ExternalShortenerProvider { get; set; } = "tinyurl";
    public int TrackingLinkValidityDays { get; set; } = 4;
}

public sealed class TelegramForwardingSettings
{
    public bool Enabled { get; set; }
    public long DestinationChatId { get; set; }
    public List<long> SourceChatIds { get; set; } = new();
    public bool AppendSheinCode { get; set; } = true;
    public bool PreferLinkPreviewWhenNoMedia { get; set; } = true;
    public string FooterText { get; set; } = "\uD83D\uDD25 Vi no: @ReiDasOfertasVIP";
}

public sealed class WhatsAppForwardingSettings
{
    public bool Enabled { get; set; }
    public bool ProcessFromMeOnly { get; set; } = true;
    public List<string> SourceChatIds { get; set; } = new();
    public List<string> DestinationGroupIds { get; set; } = new();
    public bool AppendSheinCode { get; set; } = true;
    public bool SendMediaEnabled { get; set; } = true;
    public bool PreferLinkPreviewWhenNoMedia { get; set; } = true;
    public string FooterText { get; set; } = string.Empty;
    public string? InstanceName { get; set; }
}

public sealed class WhatsAppAdminAutomationSettings
{
    public bool ParticipantCopyAutomationEnabled { get; set; }
    public bool ParticipantAddSafetyEnabled { get; set; } = true;
    public int MaxParticipantsAddedPerDay { get; set; } = 120;
    public int MinMinutesBetweenParticipantAdds { get; set; } = 10;
    public int ParticipantsAddedToday { get; set; }
    public DateTimeOffset? ParticipantAddQuotaDateUtc { get; set; }
    public DateTimeOffset? LastParticipantAddAt { get; set; }
    public List<WhatsAppInstanceParticipantAddSafetySettings> InstanceParticipantAddSafety { get; set; } = new();
    public List<WhatsAppParticipantCopySchedule> ParticipantCopySchedules { get; set; } = new();
    public List<WhatsAppScheduledGroupMessage> ScheduledGroupMessages { get; set; } = new();
    public List<WhatsAppParticipantBlastSchedule> ParticipantBlastSchedules { get; set; } = new();
    public WhatsAppInviteConversationSkillSettings InviteConversationSkill { get; set; } = new();
}

public sealed class WhatsAppInviteConversationSkillSettings
{
    public bool Enabled { get; set; } = true;
    public bool UseVariableMessages { get; set; } = true;
    public int MinPreLinkMessages { get; set; } = 2;
    public int MaxPreLinkMessages { get; set; } = 4;
    public List<string> GreetingTemplates { get; set; } =
    [
        "Oi, tudo bem por ai?",
        "Passando rapidinho: posso te mandar uma dica de oferta segura?",
        "Tudo certo? Quero te mostrar uma forma mais segura de acompanhar as ofertas."
    ];
    public List<string> ExplainTemplates { get; set; } =
    [
        "Temos um grupo oficial com ofertas validadas, menos ruido e mais seguranca para comprar sem cair em link ruim.",
        "No grupo oficial, os links passam por filtro e voce recebe oportunidades reais com menos bagunca.",
        "A ideia e te poupar tempo: ofertas revisadas e links mais confiaveis no mesmo lugar."
    ];
    public List<string> TrustTemplates { get; set; } =
    [
        "Se quiser, eu te explico em 1 minuto como entrar sem risco.",
        "Posso te mandar o acesso oficial e te orientar no primeiro passo.",
        "E rapido: eu te envio o link certo e pronto."
    ];
    public List<string> AskTemplates { get; set; } =
    [
        "Se fizer sentido pra voce, te envio o link de entrada agora.",
        "Se quiser, te mando o link oficial agora mesmo.",
        "Se topar, eu te envio o link para entrar com prioridade."
    ];
    public List<string> LinkAfterReplyTemplates { get; set; } =
    [
        "Perfeito, como voce respondeu agora, segue o link oficial para entrar: {link}",
        "Boa, vou te mandar o acesso oficial agora: {link}",
        "Fechado. Aqui esta o link oficial de entrada: {link}"
    ];
    public List<string> LinkAfterTimeoutTemplates { get; set; } =
    [
        "Como prometido, segue o link oficial para entrar no grupo: {link}",
        "Vou deixar aqui o link oficial para quando quiser entrar: {link}",
        "Sem pressa. Quando quiser, esse e o link oficial de entrada: {link}"
    ];
}

public sealed class WhatsAppInstanceParticipantAddSafetySettings
{
    public string InstanceName { get; set; } = string.Empty;
    public int MaxParticipantsAddedPerDay { get; set; } = 120;
    public int MinMinutesBetweenParticipantAdds { get; set; } = 10;
    public int ParticipantsAddedToday { get; set; }
    public DateTimeOffset? ParticipantAddQuotaDateUtc { get; set; }
    public DateTimeOffset? LastParticipantAddAt { get; set; }
}

public sealed class WhatsAppParticipantCopySchedule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Copia gradual";
    public bool Enabled { get; set; } = true;
    public string? InstanceName { get; set; }
    public string SourceGroupId { get; set; } = string.Empty;
    public string TargetGroupId { get; set; } = string.Empty;
    public List<string> PendingParticipantIds { get; set; } = new();
    public int TotalParticipants { get; set; }
    public int ProcessedParticipants { get; set; }
    public int SkippedParticipants { get; set; }
    public int BatchSize { get; set; } = 10;
    public int IntervalMinutes { get; set; } = 30;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastRunAt { get; set; }
    public DateTimeOffset NextRunAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? PausedAt { get; set; }
    public DateTimeOffset? CancelledAt { get; set; }
    public string? LastResultMessage { get; set; }
}

public sealed class WhatsAppScheduledGroupMessage
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Mensagem agendada";
    public bool Enabled { get; set; } = true;
    public string? InstanceName { get; set; }
    public string TargetGroupId { get; set; } = string.Empty;
    public string Text { get; set; } = string.Empty;
    public string? ImageUrl { get; set; }
    public int IntervalMinutes { get; set; } = 120;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastSentAt { get; set; }
    public DateTimeOffset NextRunAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? PausedAt { get; set; }
    public DateTimeOffset? CancelledAt { get; set; }
    public string? LastResultMessage { get; set; }
}

public sealed class WhatsAppParticipantBlastSchedule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Disparo para participantes";
    public bool Enabled { get; set; } = true;
    public string Status { get; set; } = "queued";
    public string? InstanceName { get; set; }
    public List<string> SourceGroupIds { get; set; } = new();
    public bool UseAllParticipantsFromSources { get; set; }
    public List<string> PendingParticipantIds { get; set; } = new();
    public List<string> SentParticipantIds { get; set; } = new();
    public int TotalParticipants { get; set; }
    public int ProcessedParticipants { get; set; }
    public int SuccessParticipants { get; set; }
    public int FailedParticipants { get; set; }
    public int RepliedParticipants { get; set; }
    public int LinksSent { get; set; }
    public string? Message { get; set; }
    public string? LinkUrl { get; set; }
    public bool UseAiDialogue { get; set; } = true;
    public int IntervalMs { get; set; } = 3500;
    public int MinUserIntervalMs { get; set; } = 3500;
    public int MaxUserIntervalMs { get; set; } = 9000;
    public int BatchSize { get; set; } = 12;
    public int BatchPauseSeconds { get; set; } = 180;
    public int PreLinkMessages { get; set; } = 3;
    public string WaitMode { get; set; } = "response-or-timeout";
    public int WaitTimeoutSeconds { get; set; } = 120;
    public bool SendLinkOnTimeout { get; set; } = false;
    public string? SecurityPitch { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? QueuedAt { get; set; }
    public DateTimeOffset? LastRunAt { get; set; }
    public DateTimeOffset? LastProgressAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? CancelledAt { get; set; }
    public string? LastResultMessage { get; set; }
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
    public bool PreferLinkPreviewWhenNoMedia { get; set; } = true;
    public string FooterText { get; set; } = string.Empty;
    public string? InstanceName { get; set; }
    public bool SkipConversionOnlyShorten { get; set; } = false;
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
    public string ReplyOnFailure { get; set; } = "Link n\u00E3o suportado.";
    public bool WelcomeEnabled { get; set; } = true;
    public string? WelcomeInstanceName { get; set; }
    public string WelcomeTargetMode { get; set; } = "private";
    public string? WelcomeTargetChatId { get; set; }
    public string WelcomeMessage { get; set; } = "REI DAS OFERTAS: oi, tudo bem? Seja muito bem-vindo ao grupo VIP. Aqui voce vai encontrar ofertas filtradas e mais seguras, com menos ruido. Eu fico a disposicao para qualquer duvida e te ajudo pessoalmente no que precisar.";
    public bool WelcomeFollowupOnYesEnabled { get; set; } = true;
    public string WelcomeFollowupOnYesMessage { get; set; } = "REI DAS OFERTAS: perfeito, vou te explicar rapidinho. Aqui no grupo a gente filtra ofertas reais, evita golpe e so publica link seguro.\n\nPara ver tudo organizado, usa nossa bio com os destaques e o site conversor para transformar qualquer link em afiliado oficial.\n\nSe bater qualquer duvida, me chama aqui que eu te ajudo pessoalmente.";
    public WhatsAppWelcomeSkillSettings WelcomeSkill { get; set; } = new();
}

public sealed class WhatsAppWelcomeSkillSettings
{
    public bool Enabled { get; set; } = true;
    public bool UseVariableMessages { get; set; } = true;
    public List<string> WelcomeTemplates { get; set; } =
    [
        "REI DAS OFERTAS: oi, tudo bem? Seja muito bem-vindo ao grupo VIP. Aqui voce vai encontrar ofertas filtradas e mais seguras, com menos ruido. Eu fico a disposicao para qualquer duvida e te ajudo pessoalmente no que precisar.",
        "REI DAS OFERTAS: obrigado por entrar no grupo VIP. A partir de agora voce recebe ofertas com filtro e links mais seguros. Se quiser, eu te explico como aproveitar melhor.",
        "REI DAS OFERTAS: bem-vindo. Valeu por entrar. Aqui a proposta e oferta real com curadoria para reduzir risco e perda de tempo."
    ];
    public List<string> FollowupOnYesTemplates { get; set; } =
    [
        "REI DAS OFERTAS: perfeito, vou te explicar rapidinho. Aqui no grupo a gente filtra ofertas reais, evita golpe e so publica link seguro.\n\nPara ver tudo organizado, usa nossa bio com os destaques e o site conversor para transformar qualquer link em afiliado oficial.\n\nSe bater qualquer duvida, me chama aqui que eu te ajudo pessoalmente.",
        "REI DAS OFERTAS: excelente. Funciona assim: monitoramos as melhores oportunidades e priorizamos link revisado. Se quiser, te mostro os atalhos da bio para acompanhar tudo organizado.",
        "REI DAS OFERTAS: obrigado pela resposta. O foco aqui e seguranca + oferta boa. Se precisar, eu te guio no passo a passo para nao perder nenhuma oportunidade importante."
    ];
}

public sealed class BioHubSettings
{
    public bool Enabled { get; set; } = true;
    public string PublicBaseUrl { get; set; } = string.Empty;
    public string BrandName { get; set; } = "Rei das Ofertas";
    public string Headline { get; set; } = "Achadinhos em destaque";
    public string Subheadline { get; set; } = "Toque no bot\u00E3o para abrir a oferta com o melhor link.";
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

public sealed class ConverterCouponAndPriceCompareSkillSettings
{
    public bool Enabled { get; set; } = true;
    public bool ShowOnWeb { get; set; } = true;
    public bool AppendToWhatsApp { get; set; } = true;
    public List<string> StoresToCompare { get; set; } = ["Amazon", "Mercado Livre", "Shopee", "Shein"];
    public int MaxComparisonResults { get; set; } = 3;
    public bool RequireExactProductMatch { get; set; } = true;
    public bool PreferOfficialData { get; set; } = true;
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
    public bool UseAi { get; set; } = true;
    public int VariationsCount { get; set; } = 2;
    public string AiProvider { get; set; } = "gemma4";
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
    public bool ViralReelsAutoPilotEnabled { get; set; }
    public long ViralReelsSourceTelegramChatId { get; set; } = 2425105459;
    public int ViralReelsIntervalHours { get; set; } = 12;
    public List<string> ViralReelsScheduleTimes { get; set; } = new() { "07:30", "17:30" };
    public int ViralReelsLookbackHours { get; set; } = 24;
    public int ViralReelsRepeatWindowHours { get; set; } = 72;
    public bool ViralReelsSendForApproval { get; set; } = true;
    public string ViralReelsApprovalChannel { get; set; } = "whatsapp";
    public string? ViralReelsApprovalWhatsAppGroupId { get; set; }
    public string? ViralReelsApprovalWhatsAppInstanceName { get; set; } = "ZapOfertas";
    public bool ViralReelsAutoPublishEnabled { get; set; }
    public bool SendToCatalog { get; set; } = false;
    public string CatalogTarget { get; set; } = CatalogTargets.Prod;
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
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "gpt-4o-mini";
    public double Temperature { get; set; } = 0.7;
    public int MaxOutputTokens { get; set; } = 700;
    public string BaseUrl { get; set; } = "https://api.openai.com/v1";
    public int MonthlyCallLimit { get; set; }
    public decimal EstimatedCostPerCallUsd { get; set; }
}

public sealed class GeminiSettings
{
    public string? ApiKey { get; set; }
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "gemini-2.5-flash";
    public string BaseUrl { get; set; } = "https://generativelanguage.googleapis.com/v1beta";
    public int MaxOutputTokens { get; set; } = 1200;
    public int MonthlyCallLimit { get; set; }
    public decimal EstimatedCostPerCallUsd { get; set; }
}

public sealed class Gemma4Settings
{
    public string? ApiKey { get; set; }
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "gemma-4-26b-a4b-it";
    public string ModelAdvanced { get; set; } = "gemma-4-31b-it";
    public string BaseUrl { get; set; } = "https://generativelanguage.googleapis.com/v1beta";
    public int MaxOutputTokens { get; set; } = 1200;
    public int MonthlyCallLimit { get; set; }
    public decimal EstimatedCostPerCallUsd { get; set; }

    /// <summary>Returns a copy of this settings using ModelAdvanced instead of Model, for heavy/complex tasks.</summary>
    public Gemma4Settings AsAdvanced() => new()
    {
        ApiKey = ApiKey,
        ApiKeys = ApiKeys,
        Model = ModelAdvanced,
        ModelAdvanced = ModelAdvanced,
        BaseUrl = BaseUrl,
        MaxOutputTokens = MaxOutputTokens,
        MonthlyCallLimit = MonthlyCallLimit,
        EstimatedCostPerCallUsd = EstimatedCostPerCallUsd
    };
}

public sealed class DeepSeekSettings
{
    public string? ApiKey { get; set; }
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "deepseek-chat";
    public double Temperature { get; set; } = 0.7;
    public int MaxOutputTokens { get; set; } = 1200;
    public string BaseUrl { get; set; } = "https://api.deepseek.com";
    public int MonthlyCallLimit { get; set; }
    public decimal EstimatedCostPerCallUsd { get; set; }
}

public sealed class NemotronSettings
{
    public string? ApiKey { get; set; }
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "nvidia/nemotron-3-super-120b-a12b";
    public double Temperature { get; set; } = 1.0;
    public double TopP { get; set; } = 0.95;
    public int MaxOutputTokens { get; set; } = 4096;
    public int ReasoningBudget { get; set; } = 4096;
    public bool EnableThinking { get; set; } = true;
    public string BaseUrl { get; set; } = "https://integrate.api.nvidia.com/v1";
    public int MonthlyCallLimit { get; set; }
    public decimal EstimatedCostPerCallUsd { get; set; }
}

public sealed class QwenSettings
{
    public string? ApiKey { get; set; }
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "qwen3.5-plus";
    public string VisionModel { get; set; } = "qwen3-vl-plus";
    public double Temperature { get; set; } = 0.7;
    public int MaxOutputTokens { get; set; } = 4096;
    public string BaseUrl { get; set; } = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1";
    public bool EnableThinking { get; set; } = true;
    public int MonthlyCallLimit { get; set; }
    public decimal EstimatedCostPerCallUsd { get; set; }
}

public sealed class VilaNvidiaSettings
{
    public string? ApiKey { get; set; }
    public List<string> ApiKeys { get; set; } = new();
    public string Model { get; set; } = "nvidia/vila";
    public double Temperature { get; set; } = 0.2;
    public double TopP { get; set; } = 0.7;
    public int MaxOutputTokens { get; set; } = 4096;
    public string BaseUrl { get; set; } = "https://integrate.api.nvidia.com/v1";
    public bool EnableThinking { get; set; } = true;
    public int MonthlyCallLimit { get; set; }
    public decimal EstimatedCostPerCallUsd { get; set; }
}

public sealed class WhatsAppAiAgentSettings
{
    /// <summary>Habilita recebimento de comandos admin via WhatsApp.</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>Prefixo que aciona o agente. Ex: "!bot"</summary>
    public string CommandPrefix { get; set; } = "!bot";

    /// <summary>JIDs (ex: 5521999999999@s.whatsapp.net) autorizados a enviar comandos.</summary>
    public List<string> AdminJids { get; set; } = new();

    /// <summary>Instância Evolution usada para enviar a resposta.</summary>
    public string? InstanceName { get; set; }

    /// <summary>Provedor de IA preferido: gemini | openai | nemotron</summary>
    public string PreferredProvider { get; set; } = "gemini";

    /// <summary>Máximo de caracteres na resposta.</summary>
    public int MaxResponseChars { get; set; } = 3000;
}

public sealed class AmazonPlaywrightScraperSettings
{
    /// <summary>Habilita o scraper Playwright como fallback antes do scraper HTML direto.</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>URL base do serviço Playwright. Ex: http://amazon-scraper:3001</summary>
    public string BaseUrl { get; set; } = "http://amazon-scraper:3001";

    /// <summary>Timeout em segundos por requisição.</summary>
    public int TimeoutSeconds { get; set; } = 35;
}

public sealed class MercadoLivreAffiliateScoutSettings
{
    public bool Enabled { get; set; }
    public bool UsePersistentSession { get; set; } = true;
    public bool Headless { get; set; } = true;
    public string? BaseUrl { get; set; } = "https://www.mercadolivre.com.br/afiliados";
    public string? LoginUrl { get; set; } = "https://www.mercadolivre.com.br/entrar?go=https%3A%2F%2Fwww.mercadolivre.com.br%2Fafiliados%2Fhub";
    public string? HomeUrl { get; set; } = "https://www.mercadolivre.com.br/afiliados/hub";
    public string? LoginUser { get; set; }
    public string? LoginPassword { get; set; }
    public string? TwoFactorCode { get; set; }
    public string? StorageStateJson { get; set; }
    public string? StorageStatePath { get; set; } = "D:\\Achadinhos\\data\\mercadolivre-affiliate-storage-state.json";
    public string? AuthMode { get; set; } = "code-or-qr";
    public string? OfferCardSelector { get; set; } = "[data-testid='recommendation-card'], [data-testid='affiliate-offer-card'], article, section";
    public string? OfferLinkSelector { get; set; } = "a[href*='/p/'], a[href*='/MLB-'], a[href*='mercadolivre.com.br/p/']";
    public string? OfferTitleSelector { get; set; } = "h2, h3, [data-testid='item-title'], [data-testid='recommendation-title']";
    public string? OfferPriceSelector { get; set; } = "[data-testid='price'], [data-testid='price-current'], .andes-money-amount__fraction";
    public string? OfferImageSelector { get; set; } = "img[src], img[data-src]";
    public string? OfferCommissionSelector { get; set; } = "[data-testid='commission'], [data-testid='extra-profit'], :text-matches('%|comiss|ganho','i')";
    public string? ShareButtonSelector { get; set; } = "button:has-text('Compartilhar oferta'), button:has-text('Compartilhar'), [data-testid='share-offer']";
    public string? ShareActionSelector { get; set; } = "button:has-text('Copiar link'), button:has-text('Gerar link'), [data-testid='copy-affiliate-link'], [data-testid='share-offer-link']";
    public string? SharedLinkSelector { get; set; } = "input[value^='http'], textarea";
    public string? SharedLinkCopyButtonSelector { get; set; } = "button:has-text('Copiar'), [data-testid='copy-link'], [data-testid='copy-affiliate-link']";
    public int IntervalMinutes { get; set; } = 10;
    public int IntervalJitterMinutes { get; set; } = 2;
    public decimal MinCommissionPercent { get; set; } = 19m;
    public decimal Tier1MinPrice { get; set; } = 99m;
    public decimal Tier1MinCommissionPercent { get; set; } = 12m;
    public decimal Tier2MinPrice { get; set; } = 189m;
    public decimal Tier2MinCommissionPercent { get; set; } = 11m;
    public decimal Tier3MinPrice { get; set; } = 325m;
    public decimal Tier3MinCommissionPercent { get; set; } = 7m;
    public int MaxOffersPerRun { get; set; } = 1;
    public int RepeatWindowHours { get; set; } = 24;
    public string? WhatsAppInstanceName { get; set; } = "ZapOfertas";
    public string? DestinationGroupId { get; set; } = "120363405661434395@g.us";
    public bool PublishViaProductionRelay { get; set; } = false;
    public string? ProductionRelayBaseUrl { get; set; } = "http://host.docker.internal:5005";
    public string? ProductionRelayAdminKey { get; set; } = "dev-local-key";
    public string? ProductionRelayInstanceName { get; set; } = "ZapOfertas";
    public bool RequireShareButtonFlow { get; set; } = true;
    public bool RequireImage { get; set; } = true;
    public bool AutoPublishToOfficialGroup { get; set; } = false;
    public bool SaveScreenshotsOnFailure { get; set; } = true;
    public string? Notes { get; set; } = "Fluxo esperado: entrar na Central de Afiliados e Criadores, abrir o hub, usar a secao 'Produtos que escolhemos para voce', abrir o produto, clicar em 'Compartilhar oferta' e copiar o link gerado. O login pode exigir codigo ou leitura de QR code.";
}
