using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AchadinhosBot.Next.Infrastructure.Media;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public class VipDesignValidation
{
    [Fact]
    public async Task ProduceVipCardSample()
    {
        var services = new ServiceCollection();
        services.AddHttpClient("default");
        var sp = services.BuildServiceProvider();
        var factory = sp.GetRequiredService<IHttpClientFactory>();

        var generator = new PromotionalCardGenerator(factory, NullLogger<PromotionalCardGenerator>.Instance);
        
        var bytes = await generator.GenerateCardAsync(
            "Tênis New Balance 413V3",
            "212,00",
            "R$ 399,00",
            "46",
            "https://opal.google/board/blobs/c6e2535c-feb6-4997-ac9e-f8006d82277c",
            CancellationToken.None);

        Assert.NotNull(bytes);

        // Save it directly to the brain artifacts directory so we can see it
        var outDir = @"C:\Users\overl\.gemini\antigravity\brain\00daeec3-5cbb-4f29-b74f-b5a8e5c459a7";
        if (!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);
        var outFile = Path.Combine(outDir, "vip_promotion_card_test.jpg");
        await File.WriteAllBytesAsync(outFile, bytes);
    }
}
