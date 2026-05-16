using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class WebhookOptions
{
    [Range(1, 65535)]
    public int Port { get; set; } = 8081;

    public string ApiKey { get; set; } = string.Empty;

    public string? PublicBaseUrl { get; set; }
}
