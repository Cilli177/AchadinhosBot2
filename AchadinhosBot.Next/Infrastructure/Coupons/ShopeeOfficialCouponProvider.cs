using AchadinhosBot.Next.Configuration;
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
}
