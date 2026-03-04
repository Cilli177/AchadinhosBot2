using System.Reflection;
using System.Text.Json;
using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class ShopeeShortLinkPayloadTests
{
    [Fact]
    public void BuildShopeePayload_IncludesFiveSubIds_FromSource()
    {
        var source = "whatsapp_grupo";
        var subIds = InvokeResolveShopeeSubIds(source);
        var payload = InvokeBuildShopeePayload("https://shopee.com.br/produto-teste", subIds);

        Assert.NotNull(payload);
        using var doc = JsonDocument.Parse(payload!);
        var query = doc.RootElement.GetProperty("query").GetString();
        Assert.NotNull(query);

        Assert.Contains("generateShortLink", query, StringComparison.Ordinal);
        Assert.Contains("originUrl: \"https://shopee.com.br/produto-teste\"", query, StringComparison.Ordinal);
        Assert.Contains("subIds: [\"whatsapp_grupo\", \"whatsapp\", \"whatsapp\", \"grupo\", \"direct\"]", query, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildShopeePayload_ReturnsNull_WhenUrlIsBlank()
    {
        var payload = InvokeBuildShopeePayload("   ", ["a", "b", "c", "d", "e"]);
        Assert.Null(payload);
    }

    private static IReadOnlyList<string> InvokeResolveShopeeSubIds(string? source)
    {
        var method = typeof(AffiliateLinkService).GetMethod(
            "ResolveShopeeSubIds",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [source]);
        Assert.NotNull(result);
        return Assert.IsAssignableFrom<IReadOnlyList<string>>(result);
    }

    private static string? InvokeBuildShopeePayload(string url, IReadOnlyList<string> subIds)
    {
        var method = typeof(AffiliateLinkService).GetMethod(
            "BuildShopeePayload",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [url, subIds]);
        return result as string;
    }
}
