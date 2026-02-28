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

    public ShopeeProductApiOptions ShopeeProductApi { get; init; } = new();

    public AmazonProductApiOptions AmazonProductApi { get; init; } = new();

    public OfficialCouponApiOptions AmazonOfficialCoupons { get; init; } = new();

    public OfficialCouponApiOptions ShopeeOfficialCoupons { get; init; } = new();

    public OfficialCouponApiOptions SheinOfficialCoupons { get; init; } = new();

    public OfficialCouponApiOptions MercadoLivreOfficialCoupons { get; init; } = new();
}

public sealed class AmazonProductApiOptions
{
    public bool Enabled { get; init; }

    public string AccessKey { get; init; } = string.Empty;

    public string SecretKey { get; init; } = string.Empty;

    public string PartnerTag { get; init; } = string.Empty;

    public string PartnerType { get; init; } = "Associates";

    public string Host { get; init; } = "webservices.amazon.com.br";

    public string Region { get; init; } = "us-east-1";

    public string Marketplace { get; init; } = "www.amazon.com.br";

    public string Path { get; init; } = "/paapi5/getitems";
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

public sealed class ShopeeProductApiOptions
{
    public bool Enabled { get; init; }

    public long PartnerId { get; init; }

    public string PartnerKey { get; init; } = string.Empty;

    public long ShopId { get; init; }

    public string Host { get; init; } = "https://partner.shopeemobile.com";
}
