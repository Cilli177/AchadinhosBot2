using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class EvolutionOptions
{
    [Required]
    public string BaseUrl { get; init; } = "http://localhost:8080";

    [Required]
    public string ApiKey { get; init; } = string.Empty;

    [Required]
    public string InstanceName { get; init; } = "achadinhos-next";

    public string? WebhookSecret { get; init; }
    public string? GroupsEndpoint { get; init; }
    public string? SendTextEndpoint { get; init; }
    public string? SendImageEndpoint { get; init; }
}
