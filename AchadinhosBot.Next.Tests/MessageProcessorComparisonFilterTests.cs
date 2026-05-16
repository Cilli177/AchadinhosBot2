using System.Reflection;
using AchadinhosBot.Next.Infrastructure.ProductData;

namespace AchadinhosBot.Next.Tests;

public sealed class MessageProcessorComparisonFilterTests
{
    [Fact]
    public void FilterSkillComparisonResults_ShouldExcludeSameStoreAndSamePrice()
    {
        var productData = new OfficialProductDataResult(
            Store: "Amazon",
            Title: "Produto Teste 1L",
            CurrentPrice: "R$ 99,90",
            PreviousPrice: "R$ 149,90",
            DiscountPercent: 33,
            Images: new List<string>(),
            IsOfficial: true,
            DataSource: "test",
            SourceUrl: "https://amazon.com.br/dp/ABC123",
            EstimatedDelivery: null,
            VideoUrl: null)
        {
            SearchResults = new List<PriceComparisonResult>
            {
                new("Amazon", "Produto Teste 1L", "R$ 79,90", "https://amazon.com.br/dp/1", null),
                new("Shopee", "Produto Teste 1L", "R$ 99,90", "https://shopee.com.br/1", null),
                new("Mercado Livre", "Produto Teste 1L", "R$ 89,90", "https://mercadolivre.com.br/1", null),
                new("Shopee", "Produto Teste 1L", "R$ 87,90", "https://shopee.com.br/2", null)
            }
        };

        var skill = new AchadinhosBot.Next.Domain.Settings.ConverterCouponAndPriceCompareSkillSettings
        {
            Enabled = true,
            AppendToWhatsApp = true,
            RequireExactProductMatch = false,
            MaxComparisonResults = 5
        };

        var method = typeof(AchadinhosBot.Next.Application.Services.MessageProcessor)
            .GetMethod("FilterSkillComparisonResults", BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);

        var results = (IReadOnlyList<object>)method!.Invoke(null, new object[] { productData, skill })!;
        var rendered = string.Join("\n", results.Select(x => x.ToString()));

        Assert.DoesNotContain("Amazon", rendered);
        Assert.DoesNotContain("R$ 99,90", rendered);
        Assert.Contains("Mercado Livre", rendered);
        Assert.Contains("Shopee", rendered);
    }
}
