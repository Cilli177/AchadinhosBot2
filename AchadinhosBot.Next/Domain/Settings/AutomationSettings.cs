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

public sealed class LinkAutomationSettings
{
    public bool AutoConvertIncomingLinks { get; set; } = true;
    public bool AutoSendToDestinationChannel { get; set; } = false;
    public string DestinationChannel { get; set; } = "@seuCanal";
}
