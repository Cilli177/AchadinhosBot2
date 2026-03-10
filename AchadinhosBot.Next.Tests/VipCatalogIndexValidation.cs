using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using AchadinhosBot.Next.Domain.Models;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public class VipCatalogIndexValidation
{
    [Fact]
    public async Task ProduceVipCatalogIndexSample()
    {
        var assembly = typeof(AchadinhosBot.Next.Configuration.AffiliateOptions).Assembly;
        var programType = assembly.GetType("Program");
        
        if (programType == null)
        {
            programType = typeof(AchadinhosBot.Next.Configuration.AffiliateOptions).Assembly.GetType("AchadinhosBot.Next.Program");
        }

        var method = programType?.GetMethod("BuildCatalogPageHtml", BindingFlags.NonPublic | BindingFlags.Static);

        var items = new List<CatalogOfferItem>
        {
            new CatalogOfferItem
            {
                ItemNumber = 1,
                ProductName = "Smartphone Apple iPhone 15 Pro Max (256 GB) - Titânio Natural",
                PriceText = "R$ 7.000,00",
                ImageUrl = "https://m.media-amazon.com/images/I/81M5wqH37LL._AC_SX679_.jpg",
                Store = "Amazon",
                PublishedAt = System.DateTimeOffset.UtcNow.AddDays(-1)
            },
            new CatalogOfferItem
            {
                ItemNumber = 2,
                ProductName = "Console PlayStation 5 Slim com Leitor de Disco",
                PriceText = "R$ 3.899,00",
                ImageUrl = "https://m.media-amazon.com/images/I/51AAL91x24L._AC_SX679_.jpg",
                Store = "Amazon",
                PublishedAt = System.DateTimeOffset.UtcNow.AddDays(-2)
            },
            new CatalogOfferItem
            {
                ItemNumber = 3,
                ProductName = "Fone de Ouvido Sem Fio AirPods Pro (2ª Geração)",
                PriceText = "R$ 1.999,00",
                ImageUrl = "https://m.media-amazon.com/images/I/61SUj2aFiwL._AC_SX679_.jpg",
                Store = "Amazon",
                PublishedAt = System.DateTimeOffset.UtcNow.AddDays(-3)
            },
            new CatalogOfferItem
            {
                ItemNumber = 4,
                ProductName = "Aspirador de Pó Robô Xiaomi Robot Vacuum E10",
                PriceText = "R$ 1.250,00",
                ImageUrl = "https://m.media-amazon.com/images/I/51uI-G5E-PL._AC_SX679_.jpg",
                Store = "Amazon",
                PublishedAt = System.DateTimeOffset.UtcNow.AddDays(-4)
            }
        };
        
        var currentUrl = "https://achadinhos.tv.br/catalogo";

        Assert.NotNull(method);
        var html = (string)method.Invoke(null, new object[] { items, "", currentUrl })!;

        var outDir = @"C:\Users\overl\.gemini\antigravity\brain\00daeec3-5cbb-4f29-b74f-b5a8e5c459a7";
        if (!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);
        var outFile = Path.Combine(outDir, "vip_catalog_index_preview.html");
        await File.WriteAllTextAsync(outFile, html);
    }
}
