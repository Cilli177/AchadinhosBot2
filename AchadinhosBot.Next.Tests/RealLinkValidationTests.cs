using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Amazon;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Xunit.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class RealLinkValidationTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly HttpClient _httpClient;

    public RealLinkValidationTests(ITestOutputHelper output)
    {
        _output = output;
        
        var handler = new HttpClientHandler { AllowAutoRedirect = true };
        _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0");
    }

    [Fact]
    public async Task ValidateRealUserLinks_WithFallbackLogic()
    {
        var urls = new[]
        {
            "https://meli.la/2Dkanv9",
            "https://meli.la/1WBiGnw",
            "https://meli.la/2ia6LeB",
            "https://www.mercadolivre.com.br/social/minutoreview?matt_word=telegramheroi&matt_tool=35882011&forceInApp=true&ref=BMMez9FWROpEI2Tonw6Os0QcGKSyaYJ2EsP2hCySofjJ1qn18R5kzeGNvPFFulNW%2FvlKrty72VicaYnOM6aS1ni%2Bvp6zaaNxzCdyFZHV%2F6yez37OPY4V1ZdSsy%2Bwj5GT1utUKxm26PGNcwxob%2FyMWft9j7669p1QoiMHTnYauU1cjrAlukvvWySe7Mq1VVMCRs%2Bom2E%3D",
            "https://www.mercadolivre.com.br/social/minutoreview?matt_word=telegramheroi&matt_tool=35882011&forceInApp=true&ref=BMXzRdVqpzByEEJOfc1yIaU2psHV36GRN1h1%2F747AqM%2BVeiAeTzVOw9nQoRDBtcPNWVQLJjkGMji%2BP5hr9rrDS4GTnIMIWYT%2F9JmbcQUcZ5eTZuRdJcCS3%2FCWaJ4gB8TEaHT5bQn0XXKv5KAbxhB44pnKG0j9IASCytZPEDGGIn0rnAvTs7hvcyoc%2BqCVIHmtUXNeg%3D%3D",
            "https://produto.mercadolivre.com.br/MLB-5519729802-tnis-ultimashow-20-adidas-_JM?searchVariation=189185285371&matt_event_ts=1772807658914&matt_d2id=1942c124-ad68-42fc-8c23-b0cd95055fea&matt_tracing_id=6e62affa-2815-4074-8ed9-230f50041356",
            "https://www.mercadolivre.com.br/tnis-casual-masculino-only-2-olympikus/p/MLB27307234?pdp_filters=item_id:MLB3467275109"
        };

        var service = CreateRealService();

        int i = 1;
        foreach (var url in urls)
        {
            _output.WriteLine($"\n--- Testando Link {i++} ---");
            _output.WriteLine($"Original: {url}");

            var result = await service.ConvertAsync(url, CancellationToken.None, "teste_manual");

            _output.WriteLine($"Sucesso:  {result.Success}");
            _output.WriteLine($"Afiliado: {result.IsAffiliated}");
            
            if (result.Success)
            {
                _output.WriteLine($"URL Final: {result.ConvertedUrl}");
            }
            else
            {
                _output.WriteLine($"ERRO/BLOQUEIO: {result.ValidationError ?? result.Error}");
            }
            
            await Task.Delay(1000);
        }
    }

    private AffiliateLinkService CreateRealService()
    {
        var options = Options.Create(new AffiliateOptions
        {
            MercadoLivreMattTool = "98187057",
            MercadoLivreMattWord = "land177",
            MercadoLivreRequireOAuth = false,
            LinkTagging = new AffiliateLinkTaggingOptions()
        });

        var httpClientFactory = new RealHttpClientFactory(_httpClient);
        var creator = new AmazonCreatorApiClient(options, httpClientFactory, NullLogger<AmazonCreatorApiClient>.Instance);
        var paApi = new AmazonPaApiClient(options, httpClientFactory, NullLogger<AmazonPaApiClient>.Instance);
        
        return new AffiliateLinkService(options, new FakeMercadoLivreOAuthService(), creator, paApi, NullLogger<AffiliateLinkService>.Instance, httpClientFactory);
    }

    private sealed class RealHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
    
    private sealed class FakeMercadoLivreOAuthService : Application.Abstractions.IMercadoLivreOAuthService
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task<Application.Abstractions.MercadoLivreOAuthStatus> GetStatusAsync(CancellationToken cancellationToken)
            => Task.FromResult(new Application.Abstractions.MercadoLivreOAuthStatus(false, true, "oauth_mock", null, null, null, null, false));
        public Task<Application.Abstractions.MercadoLivreOAuthStatus> RefreshAndCheckAsync(CancellationToken cancellationToken)
            => GetStatusAsync(cancellationToken);
    }
    
    public void Dispose()
    {
        _httpClient.Dispose();
    }
}
