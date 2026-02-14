using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class WebhookOptions
{
    [Range(1, 65535)]
    public int Port { get; init; } = 8081;

    [Required]
    public string ApiKey { get; init; } = string.Empty;

    public string? PublicBaseUrl { get; init; }
}
