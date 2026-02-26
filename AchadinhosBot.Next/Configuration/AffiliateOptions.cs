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

    public OfficialCouponApiOptions AmazonOfficialCoupons { get; init; } = new();

    public OfficialCouponApiOptions ShopeeOfficialCoupons { get; init; } = new();

    public OfficialCouponApiOptions SheinOfficialCoupons { get; init; } = new();

    public OfficialCouponApiOptions MercadoLivreOfficialCoupons { get; init; } = new();
}

public sealed class OfficialCouponApiOptions
{
    public bool Enabled { get; init; }

    public string Endpoint { get; init; } = string.Empty;

    public string Method { get; init; } = "GET";

    public string PayloadJson { get; init; } = string.Empty;

    public string ApiKeyHeader { get; init; } = "X-API-Key";

    public string ApiKey { get; init; } = string.Empty;

    public string BearerToken { get; init; } = string.Empty;

    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}
