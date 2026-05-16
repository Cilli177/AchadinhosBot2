using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class EvolutionOptions
{
    [Required]
    public string BaseUrl { get; set; } = "http://localhost:8080";

    [Required]
    public string ApiKey { get; set; } = string.Empty;

    [Required]
    public string InstanceName { get; set; } = "achadinhos-next";

    public string? WebhookSecret { get; set; }
    public string? GroupsEndpoint { get; set; }
    public string? SendTextEndpoint { get; set; }
    public string? SendImageEndpoint { get; set; }
}
