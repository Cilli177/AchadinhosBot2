using System.Runtime.Serialization;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.ProductData;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class Gemma4CopyGenerationTests
{
    [Fact]
    public async Task Gemma4_GeraLegendaPersuasiva_ComProdutoELinkConvertido()
    {
        const string productName = "Panela de Pressão Brinox 4,2L Bege Vanilla";
        const string convertedLink = "https://reidasofertas.ia.br/r/ML-000354";

        var promptSettings = new InstagramPostSettings
        {
            UseAi = true,
            AiProvider = "gemma4",
            UseUltraPrompt = true,
            VariationsCount = 2,
            PromptPreset = "premium"
        };

        var prompt = OpenAiInstagramPostGenerator.BuildPrompt(
            productName,
            "Oferta recebida e link convertido para afiliado oficial.",
            convertedLink,
            new List<string>(),
            productName,
            "Produto de destaque para o canal AE-IA 3000 - VIDEOS VIRAIS.",
            promptSettings);

        var responseText = """
        Legenda 1: A Panela de Pressão Brinox 4,2L Bege Vanilla junta praticidade, presença e utilidade real para a cozinha do dia a dia.

        Legenda 2: Se a ideia é levar um achado bonito e funcional para casa sem complicar a compra, essa oferta merece ficar no topo da lista.

        CTA: Comente QUERO e clique no link convertido para conferir o preço atualizado antes que mude: https://reidasofertas.ia.br/r/ML-000354

        Hashtags sugeridas: #achadinhos #ofertas #promoção #compras #tecnologia
        """;

        var handler = new CapturingGeminiHandler(responseText);
        using var httpClientFactory = new FakeHttpClientFactory(handler);
        var generator = new GeminiInstagramPostGenerator(
            httpClientFactory,
            NullLogger<GeminiInstagramPostGenerator>.Instance,
            new StubAiLogStore(),
            CreateUninitialized<InstagramLinkMetaService>(),
            CreateUninitialized<InstagramImageDownloadService>(),
            CreateUninitialized<OfficialProductDataService>());

        var gemma4 = new Gemma4Settings
        {
            ApiKey = "test-key",
            ApiKeys = new List<string> { "test-key" },
            Model = "gemma-4-26b-a4b-it",
            ModelAdvanced = "gemma-4-31b-it",
            MaxOutputTokens = 1200
        };

        var output = await generator.GenerateFreeformAsync(prompt, gemma4.AsAdvanced(), CancellationToken.None);

        Assert.NotNull(output);
        Assert.Contains("Brinox 4,2L Bege Vanilla", handler.LastRequestBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(convertedLink, handler.LastRequestBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Nao mostre pensamento", handler.LastRequestBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("gemma-4-31b-it", handler.LastRequestUri?.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains(productName, output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(convertedLink, output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Comente QUERO", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Hashtags sugeridas", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InstagramWorkflowSupport_GeraCopysDistintasParaInstagramEWhatsApp()
    {
        var instagram = InstagramWorkflowSupport.BuildInstagramCaption(
            "A Lava-Loucas Praxis Portatil LLPP resolve a rotina. https://s.shopee.com.br/16dX6wzWu",
            "Lava-Loucas Praxis Portatil LLPP Semi Automatica 127V Preto",
            sendToCatalog: true);

        var whatsapp = InstagramWorkflowSupport.BuildWhatsAppCaption(
            "A Lava-Loucas Praxis Portatil LLPP resolve a rotina. https://s.shopee.com.br/16dX6wzWu",
            "Lava-Loucas Praxis Portatil LLPP Semi Automatica 127V Preto",
            "https://s.shopee.com.br/16dX6wzWu",
            currentPrice: "R$ 999,90",
            previousPrice: "R$ 1.199,90",
            discountPercent: 17);

        Assert.DoesNotContain("https://s.shopee.com.br/16dX6wzWu", instagram, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Curadoria premium", instagram, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Acesse a bio e entre no catalogo", instagram, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ACHADO FORTE DO REI DAS OFERTAS", whatsapp, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://s.shopee.com.br/16dX6wzWu", whatsapp, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Acesse a bio e entre no catalogo", whatsapp, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InstagramWorkflowSupport_NaoRepetePrecoQuandoDeEPorSaoIguais()
    {
        var whatsapp = InstagramWorkflowSupport.BuildWhatsAppCaption(
            "Produto bonito para renovar a casa.",
            "Canto Alemão Victor com 2 Cadeiras",
            "https://s.shopee.com.br/7KtQfFaXsD",
            currentPrice: "R$ 1.527,07",
            previousPrice: "R$ 1.527,07",
            discountPercent: 50);

        Assert.Contains("💰 Por: R$ 1.527,07", whatsapp, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("De: R$ 1.527,07", whatsapp, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Desconto aproximado: 50%", whatsapp, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("🔥", whatsapp, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("👉 Pegar oferta:", whatsapp, StringComparison.OrdinalIgnoreCase);
    }

    private static T CreateUninitialized<T>() where T : class
        => (T)FormatterServices.GetUninitializedObject(typeof(T));

    private sealed class CapturingGeminiHandler : HttpMessageHandler
    {
        private readonly string _responseText;

        public CapturingGeminiHandler(string responseText)
        {
            _responseText = responseText;
        }

        public string? LastRequestUri { get; private set; }
        public string? LastRequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri?.ToString();
            LastRequestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

            var payload = new
            {
                candidates = new[]
                {
                    new
                    {
                        content = new
                        {
                            parts = new[]
                            {
                                new { text = _responseText }
                            }
                        }
                    }
                }
            };

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload))
            };
        }
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory, IDisposable
    {
        private readonly HttpClient _client;

        public FakeHttpClientFactory(HttpMessageHandler handler)
        {
            _client = new HttpClient(handler, disposeHandler: false);
        }

        public HttpClient CreateClient(string name) => _client;

        public void Dispose() => _client.Dispose();
    }

    private sealed class StubAiLogStore : IInstagramAiLogStore
    {
        public Task AppendAsync(AchadinhosBot.Next.Domain.Logs.InstagramAiLogEntry entry, CancellationToken ct) => Task.CompletedTask;

        public Task<IReadOnlyList<AchadinhosBot.Next.Domain.Logs.InstagramAiLogEntry>> ListAsync(int take, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<AchadinhosBot.Next.Domain.Logs.InstagramAiLogEntry>>(Array.Empty<AchadinhosBot.Next.Domain.Logs.InstagramAiLogEntry>());

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
