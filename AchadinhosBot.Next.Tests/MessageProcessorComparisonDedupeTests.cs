using System.Collections;
using System.Reflection;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.ProductData;

namespace AchadinhosBot.Next.Tests;

public sealed class MessageProcessorComparisonDedupeTests
{
    [Fact]
    public void FilterSkillComparisonResults_KeepsCheapestPerStore_WhenSameStoreDuplicates()
    {
        var method = GetMethod();

        var productData = new OfficialProductDataResult(
            Store: "Shopee",
            Title: "Fone Bluetooth X",
            CurrentPrice: "R$ 199,90",
            PreviousPrice: null,
            DiscountPercent: null,
            Images: [],
            IsOfficial: true,
            DataSource: "test",
            SourceUrl: "https://shopee.com.br/TEST",
            SearchResults:
            [
                new PriceComparisonResult("Amazon", "Fone Bluetooth X", "R$ 199,90", "https://www.amazon.com.br/dp/B0TEST123?tag=aaa"),
                new PriceComparisonResult("Amazon", "Fone Bluetooth X", "199,90", "https://www.amazon.com.br/dp/B0TEST123#oferta"),
                new PriceComparisonResult("Amazon", "Fone Bluetooth X", "R$ 189,90", "https://www.amazon.com.br/dp/B0TEST999")
            ]);

        var skill = new ConverterCouponAndPriceCompareSkillSettings
        {
            Enabled = true,
            AppendToWhatsApp = true,
            RequireExactProductMatch = false,
            MaxComparisonResults = 6,
            StoresToCompare = []
        };

        var entries = InvokeFilter(method, productData, skill);

        // All 3 are Amazon — one-per-store dedup collapses to 1 (cheapest = B0TEST999 at R$189,90).
        Assert.Equal(1, entries.Count);
        var url = entries[0].GetType().GetProperty("Url")!.GetValue(entries[0])?.ToString();
        Assert.Contains("B0TEST999", url, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FilterSkillComparisonResults_OneEntryPerStore_WhenMultipleStores()
    {
        var method = GetMethod();

        var productData = new OfficialProductDataResult(
            Store: "Amazon",
            Title: "Tenis Nike Air Max",
            CurrentPrice: "R$ 399,00",
            PreviousPrice: null,
            DiscountPercent: null,
            Images: [],
            IsOfficial: true,
            DataSource: "test",
            SourceUrl: "https://amazon.com.br/dp/NIKE1",
            SearchResults:
            [
                new PriceComparisonResult("Mercado Livre", "Nike Air Max", "R$ 420,00", "https://www.mercadolivre.com.br/p/ML1"),
                new PriceComparisonResult("Mercado Livre", "Nike Air Max 270", "R$ 380,00", "https://www.mercadolivre.com.br/p/ML2"),
                new PriceComparisonResult("Shopee", "Nike Air Max", "R$ 350,00", "https://shopee.com.br/produto/SHOP1"),
                new PriceComparisonResult("Shopee", "Nike Air Max - importado", "R$ 330,00", "https://shopee.com.br/produto/SHOP2"),
                new PriceComparisonResult("Amazon", "Nike Air Max", "R$ 410,00", "https://www.amazon.com.br/dp/NIKE2"),
            ]);

        var skill = new ConverterCouponAndPriceCompareSkillSettings
        {
            Enabled = true,
            AppendToWhatsApp = true,
            RequireExactProductMatch = false,
            MaxComparisonResults = 6,
            StoresToCompare = []
        };

        var entries = InvokeFilter(method, productData, skill);

        // One entry per store, excluding the primary store (Amazon) — 2 distinct stores.
        var stores = entries
            .Select(x => x.GetType().GetProperty("Store")!.GetValue(x)?.ToString())
            .ToList();

        Assert.Equal(2, entries.Count);
        Assert.Contains(stores, s => string.Equals(s, "Mercado Livre", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(stores, s => string.Equals(s, "Shopee", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(stores, s => string.Equals(s, "Amazon", StringComparison.OrdinalIgnoreCase));

        // Mercado Livre cheapest = ML2 (R$380); Shopee cheapest = SHOP2 (R$330)
        var urls = entries
            .Select(x => x.GetType().GetProperty("Url")!.GetValue(x)?.ToString())
            .ToList();
        Assert.Contains(urls, u => u!.Contains("ML2", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(urls, u => u!.Contains("SHOP2", StringComparison.OrdinalIgnoreCase));
    }

    private static MethodInfo GetMethod()
    {
        var method = typeof(MessageProcessor).GetMethod(
            "FilterSkillComparisonResults",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return method!;
    }

    private static List<object> InvokeFilter(
        MethodInfo method,
        OfficialProductDataResult productData,
        ConverterCouponAndPriceCompareSkillSettings skill)
    {
        var raw = method.Invoke(null, new object[] { productData, skill });
        Assert.NotNull(raw);
        return ((IEnumerable)raw!).Cast<object>().ToList();
    }
}
