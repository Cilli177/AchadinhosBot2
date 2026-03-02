using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Coupons;

public sealed class AmazonOfficialCouponProvider : OfficialCouponProviderBase
{
    public AmazonOfficialCouponProvider(
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<AmazonOfficialCouponProvider> logger)
        : base(affiliateOptions, httpClientFactory, logger)
    {
    }

    public override string Store => "Amazon";

    protected override OfficialCouponApiOptions GetApiOptions(AffiliateOptions options)
        => options.AmazonOfficialCoupons;
}
