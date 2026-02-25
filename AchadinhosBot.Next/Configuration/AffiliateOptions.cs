using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class AffiliateOptions
{
    [Required]
    public string AmazonTag { get; init; } = string.Empty;

    [Required]
    public string SheinId { get; init; } = string.Empty;

    public string SheinCode { get; init; } = string.Empty;

    public string MercadoLivreMattTool { get; init; } = string.Empty;

    public string MercadoLivreMattWord { get; init; } = string.Empty;

    public string MercadoLivreClientId { get; init; } = string.Empty;

    public string MercadoLivreClientSecret { get; init; } = string.Empty;

    public string MercadoLivreRefreshToken { get; init; } = string.Empty;

    public string MercadoLivreUserId { get; init; } = string.Empty;

    public bool MercadoLivreRequireOAuth { get; init; }

    public string ShopeeAppId { get; init; } = string.Empty;

    public string ShopeeSecret { get; init; } = string.Empty;
}
