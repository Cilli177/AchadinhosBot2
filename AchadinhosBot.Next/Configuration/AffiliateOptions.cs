using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class AffiliateOptions
{
    [Required]
    public string AmazonTag { get; init; } = string.Empty;

    [Required]
    public string SheinId { get; init; } = string.Empty;

    public string SheinCode { get; init; } = string.Empty;
}
