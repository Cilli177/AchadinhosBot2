using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Coupons;

public sealed class MercadoLivreOfficialCouponProvider : OfficialCouponProviderBase
{
    public MercadoLivreOfficialCouponProvider(
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<MercadoLivreOfficialCouponProvider> logger)
        : base(affiliateOptions, httpClientFactory, logger)
    {
    }

    public override string Store => "Mercado Livre";

    protected override OfficialCouponApiOptions GetApiOptions(AffiliateOptions options)
        => options.MercadoLivreOfficialCoupons;
}
