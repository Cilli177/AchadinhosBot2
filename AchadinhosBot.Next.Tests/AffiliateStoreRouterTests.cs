using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class AffiliateStoreRouterTests
{
    [Theory]
    [InlineData("https://www.amazon.com.br/dp/B08N5M7S6K", AffiliateStoreRouter.Amazon)]
    [InlineData("https://amzn.to/4squJ9F", AffiliateStoreRouter.Amazon)]
    [InlineData("https://www.mercadolivre.com.br/p/MLB19761624", AffiliateStoreRouter.MercadoLivre)]
    [InlineData("https://meli.la/2J9DirG", AffiliateStoreRouter.MercadoLivre)]
    [InlineData("https://s.shopee.com.br/AUpvSsCTgY", AffiliateStoreRouter.Shopee)]
    [InlineData("https://br.shein.com/produto.html", AffiliateStoreRouter.Shein)]
    [InlineData("https://example.com/oferta", AffiliateStoreRouter.Unknown)]
    public void ResolveStore_MapsSupportedHosts(string url, string expectedStore)
    {
        var store = AffiliateStoreRouter.ResolveStore(new Uri(url));

        Assert.Equal(expectedStore, store);
    }

    [Theory]
    [InlineData(" WWW.AMAZON.COM.BR. ", "www.amazon.com.br")]
    [InlineData("s.shopee.com.br\u200b", "s.shopee.com.br")]
    public void NormalizeHost_RemovesNoiseAndLowercases(string host, string expected)
    {
        Assert.Equal(expected, AffiliateStoreRouter.NormalizeHost(host));
    }
}
