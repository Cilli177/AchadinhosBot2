using AchadinhosBot.Next.Configuration;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Coupons;

public sealed class ShopeeOfficialCouponProvider : OfficialCouponProviderBase
{
    public ShopeeOfficialCouponProvider(
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<ShopeeOfficialCouponProvider> logger)
        : base(affiliateOptions, httpClientFactory, logger)
    {
    }

    public override string Store => "Shopee";

    protected override OfficialCouponApiOptions GetApiOptions(AffiliateOptions options)
        => options.ShopeeOfficialCoupons;

    protected override HttpRequestMessage BuildRequest(OfficialCouponApiOptions options)
    {
        var request = base.BuildRequest(options);

        if (string.IsNullOrWhiteSpace(AffiliateOptions.ShopeeAppId) || string.IsNullOrWhiteSpace(AffiliateOptions.ShopeeSecret))
        {
            return request;
        }

        var payload = options.PayloadJson ?? string.Empty;
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signature = ComputeShopeeSignature(AffiliateOptions.ShopeeAppId.Trim(), AffiliateOptions.ShopeeSecret.Trim(), timestamp, payload);
        request.Headers.Remove("Authorization");
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            $"SHA256 Credential={AffiliateOptions.ShopeeAppId.Trim()}, Timestamp={timestamp}, Signature={signature}");

        return request;
    }

    private static string ComputeShopeeSignature(string appId, string secret, long timestamp, string bodyJson)
    {
        var raw = $"{appId}{timestamp}{bodyJson}{secret}";
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
