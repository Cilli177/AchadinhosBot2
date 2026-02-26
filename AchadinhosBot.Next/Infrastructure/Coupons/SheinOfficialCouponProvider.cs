using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Coupons;

public sealed class SheinOfficialCouponProvider : OfficialCouponProviderBase
{
    public SheinOfficialCouponProvider(
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<SheinOfficialCouponProvider> logger)
        : base(affiliateOptions, httpClientFactory, logger)
    {
    }

    public override string Store => "Shein";

    protected override OfficialCouponApiOptions GetApiOptions(AffiliateOptions options)
        => options.SheinOfficialCoupons;
}
