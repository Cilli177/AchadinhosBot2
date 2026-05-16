using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Tests;

public sealed class OfferNormalizationServiceTests
{
    private readonly OfferNormalizationService _service = new();

    [Fact]
    public void Normalize_JsonPayload_MapsCanonicalOffers()
    {
        const string raw = """
        {
          "offers": [
            {
              "source": "Shopee",
              "product_name": "Fone Bluetooth",
              "product_url": "https://example.com/fone",
              "original_price": 199.90,
              "promo_price": 129.90,
              "store_name": "Loja X",
              "category": "Eletronicos",
              "commission_raw": "12%"
            }
          ]
        }
        """;

        var run = _service.Normalize(raw, "json", OfferNormalizationTargets.Review, "json test", "tester");

        Assert.Equal("json", run.SourceType);
        Assert.Equal(OfferNormalizationStatuses.Normalized, run.Status);
        Assert.Single(run.NormalizedOffers);

        var offer = run.NormalizedOffers[0];
        Assert.Equal("Shopee", offer.Source);
        Assert.Equal("Fone Bluetooth", offer.ProductName);
        Assert.Equal("https://example.com/fone", offer.ProductUrl);
        Assert.Equal(199.90m, offer.OriginalPrice);
        Assert.Equal(129.90m, offer.PromoPrice);
        Assert.Equal("Loja X", offer.StoreName);
        Assert.Equal("Eletronicos", offer.Category);
        Assert.Equal("12%", offer.CommissionRaw);
        Assert.NotEmpty(run.Summary);
    }

    [Fact]
    public void Normalize_CsvPayload_ComputesDiscountWhenMissing()
    {
        const string raw = """
        source,product_name,product_url,original_price,promo_price,store_name,category,commission_raw
        Mercado Livre,Cafeteira,https://example.com/cafeteira,500,350,Loja Oficial,Casa,8%
        """;

        var run = _service.Normalize(raw, "csv", OfferNormalizationTargets.Catalog, null, "tester");

        Assert.Equal("csv", run.SourceType);
        Assert.Equal(OfferNormalizationStatuses.Normalized, run.Status);
        Assert.Single(run.NormalizedOffers);

        var offer = run.NormalizedOffers[0];
        Assert.Equal(30m, offer.DiscountPercent);
        Assert.Equal("Mercado Livre", offer.Source);
        Assert.Equal("Cafeteira", offer.ProductName);
        Assert.Empty(run.ValidationIssues.Where(x => string.Equals(x.Level, "error", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void Normalize_EmptyInput_ReturnsFailedRunWithIssue()
    {
        var run = _service.Normalize("", null, OfferNormalizationTargets.Queue, null, "tester");

        Assert.Equal(OfferNormalizationStatuses.Failed, run.Status);
        Assert.Empty(run.NormalizedOffers);
        Assert.NotEmpty(run.ValidationIssues);
        Assert.Contains(run.ValidationIssues, x => string.Equals(x.Level, "error", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Route_ReviewTarget_ProducesReviewRequiredStatus()
    {
        const string raw = """
        product_name,product_url,promo_price
        Produto A,https://example.com/a,99.90
        """;

        var run = _service.Normalize(raw, "csv", OfferNormalizationTargets.Review, null, "tester");
        var routed = _service.Route(run, OfferNormalizationTargets.Review, "manter em revisão");

        Assert.Equal(OfferNormalizationTargets.Review, routed.SelectedTarget);
        Assert.Equal(OfferNormalizationStatuses.ReviewRequired, routed.Status);
        Assert.Equal("manter em revisão", routed.Notes);
    }
}
