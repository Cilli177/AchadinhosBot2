using System.Reflection;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Infrastructure.Storage;
namespace AchadinhosBot.Next.Tests;

public sealed class CatalogOfferStoreTests
{
    [Fact]
    public void ResolveOfferUrl_ShouldPreferOriginalOfferUrl_WhenPresent()
    {
        var method = typeof(CatalogOfferStore).GetMethod("ResolveOfferUrl", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var draft = new InstagramPublishDraft
        {
            OriginalOfferUrl = "https://www.mercadolivre.com.br/p/MLB12345678",
            OfferUrl = "https://reidasofertas.ia.br/r/ML-000250"
        };

        var result = (string)method!.Invoke(null, new object[] { draft })!;

        Assert.Equal("https://www.mercadolivre.com.br/p/MLB12345678", result);
    }

    [Fact]
    public async Task ListAsync_ShouldRecoverFromLatestProdBackupWhenPrimaryFileIsEmpty()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "achadinhos-catalog-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var dataDir = Path.Combine(tempDir, "data");
        var versionsDir = Path.Combine(dataDir, "versions");
        Directory.CreateDirectory(versionsDir);

        var primaryPath = Path.Combine(dataDir, "catalog-offers.prod.json");
        await File.WriteAllTextAsync(primaryPath, string.Empty);

        var backupPath = Path.Combine(versionsDir, $"catalog-offers.prod.{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.json.bak");
        await File.WriteAllTextAsync(backupPath, """
        {
          "NextItemNumber": 11,
          "Items": [
            {
              "ItemNumber": 1,
              "Keyword": "CREATINA",
              "DraftId": "87ec7ed462e647a4a6c814231deca8ec",
              "ProductName": "Creatina Monohidratada Pura 1kg Dark Lab Unidade Sem sabor - R$ 69,9",
              "Store": "Loja",
              "OfferUrl": "https://meli.la/22qR7Py",
              "Active": true,
              "CatalogTarget": "prod"
            }
          ]
        }
        """);

        var store = new CatalogOfferStore(null, dataDir);
        var items = await store.ListAsync(null, 20, CancellationToken.None, catalogTarget: "prod");

        Assert.NotEmpty(items);
    }
}
