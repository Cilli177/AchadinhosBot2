using System.Net;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Compliance;
using AchadinhosBot.Next.Infrastructure.Safety;
using AchadinhosBot.Next.Infrastructure.WhatsApp;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace AchadinhosBot.Next.Tests;

public sealed class EvolutionWhatsAppGatewayTests
{
    [Fact]
    public async Task SendTextAsync_TriesTextMessagePayload_WhenFlatPayloadFails()
    {
        var handler = new RecordingEvolutionHandler((request, body) =>
        {
            if (request.Method == HttpMethod.Get && request.RequestUri?.AbsolutePath.Contains("/instance/connectionState/", StringComparison.OrdinalIgnoreCase) == true)
            {
                return OkJson("""{"instance":{"state":"open"}}""");
            }

            if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath.Contains("/message/sendText/", StringComparison.OrdinalIgnoreCase) == true)
            {
                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty("textMessage", out _)
                    ? OkJson("""{"status":"PENDING"}""")
                    : BadJson("""{"message":["[object Object]"]}""");
            }

            return BadJson("{}");
        });
        var gateway = CreateGateway(handler);

        var result = await gateway.SendTextAsync("ZapOfertas", "120363409272515351@g.us", "teste", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains(handler.PostBodies, body => body.Contains("\"textMessage\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SendImageUrlAsync_TriesMediaMessagePayload_WhenFlatPayloadFails()
    {
        var handler = new RecordingEvolutionHandler((request, body) =>
        {
            if (request.Method == HttpMethod.Get && request.RequestUri?.AbsolutePath.Contains("/instance/connectionState/", StringComparison.OrdinalIgnoreCase) == true)
            {
                return OkJson("""{"instance":{"state":"open"}}""");
            }

            if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath.Contains("/message/sendMedia/", StringComparison.OrdinalIgnoreCase) == true)
            {
                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty("mediaMessage", out var mediaMessage) &&
                       mediaMessage.TryGetProperty("media", out var media) &&
                       media.GetString() == "https://cdn.example.com/oferta.jpg"
                    ? OkJson("""{"status":"PENDING"}""")
                    : BadJson("""{"message":["Owned media must be a url or base64"]}""");
            }

            return BadJson("{}");
        });
        var gateway = CreateGateway(handler);

        var result = await gateway.SendImageUrlAsync(
            "ZapOfertas",
            "120363409272515351@g.us",
            "https://cdn.example.com/oferta.jpg",
            "caption",
            "image/jpeg",
            "oferta.jpg",
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains(handler.PostBodies, body => body.Contains("\"mediaMessage\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SendImageUrlAsync_TranscodesDownloadedImageToJpegBase64Fallback()
    {
        byte[] imageBytes;
        using (var image = new Image<Rgba32>(2, 2, Color.Red))
        using (var stream = new MemoryStream())
        {
            image.SaveAsPng(stream);
            imageBytes = stream.ToArray();
        }
        var handler = new RecordingEvolutionHandler((request, body) =>
        {
            if (request.Method == HttpMethod.Get && request.RequestUri?.AbsolutePath.Contains("/instance/connectionState/", StringComparison.OrdinalIgnoreCase) == true)
            {
                return OkJson("""{"instance":{"state":"open"}}""");
            }

            if (request.Method == HttpMethod.Get && request.RequestUri?.Host == "cdn.example.com")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(imageBytes)
                    {
                        Headers = { ContentType = new("image/png") }
                    }
                };
            }

            if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath.Contains("/message/sendMedia/", StringComparison.OrdinalIgnoreCase) == true)
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("media", out var media) &&
                    media.ValueKind == JsonValueKind.String &&
                    media.GetString() is { } value &&
                    !value.StartsWith("http", StringComparison.OrdinalIgnoreCase) &&
                    doc.RootElement.TryGetProperty("mimetype", out var mimetype) &&
                    mimetype.GetString() == "image/jpeg")
                {
                    return OkJson("""{"status":"PENDING"}""");
                }

                return BadJson("""{"message":["Owned media must be a url or base64"]}""");
            }

            return BadJson("{}");
        });
        var gateway = CreateGateway(handler);

        var result = await gateway.SendImageUrlAsync(
            "ZapOfertas",
            "120363409272515351@g.us",
            "https://cdn.example.com/oferta.webp",
            "caption",
            "image/webp",
            "oferta.webp",
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains(handler.PostBodies, body =>
            body.Contains("\"mimetype\":\"image/jpeg\"", StringComparison.Ordinal) &&
            body.Contains("\"fileName\":\"oferta.jpg\"", StringComparison.Ordinal));
    }

    private static EvolutionWhatsAppGateway CreateGateway(HttpMessageHandler handler)
    {
        return new EvolutionWhatsAppGateway(
            new StubHttpClientFactory(handler),
            Options.Create(new EvolutionOptions
            {
                BaseUrl = "http://evolution.local",
                ApiKey = "test-key",
                InstanceName = "ZapOfertas"
            }),
            new DeliverySafetyPolicy(
                new StubHostEnvironment(),
                Options.Create(new DeliverySafetyOptions())),
            new StubApprovalStore(),
            NullLogger<EvolutionWhatsAppGateway>.Instance);
    }

    private static HttpResponseMessage OkJson(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json)
    };

    private static HttpResponseMessage BadJson(string json) => new(HttpStatusCode.BadRequest)
    {
        Content = new StringContent(json)
    };

    private sealed class RecordingEvolutionHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, string, HttpResponseMessage> _responder;

        public RecordingEvolutionHandler(Func<HttpRequestMessage, string, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        public List<string> PostBodies { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);

            if (request.Method == HttpMethod.Post)
            {
                PostBodies.Add(body);
            }

            return _responder(request, body);
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public StubHttpClientFactory(HttpMessageHandler handler)
        {
            _handler = handler;
        }

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    private sealed class StubApprovalStore : IMercadoLivreApprovalStore
    {
        public Task AppendAsync(MercadoLivrePendingApproval entry, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<MercadoLivrePendingApproval>> ListAsync(string? status, int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MercadoLivrePendingApproval>>(Array.Empty<MercadoLivrePendingApproval>());
        public Task<MercadoLivrePendingApproval?> GetAsync(string id, CancellationToken cancellationToken) => Task.FromResult<MercadoLivrePendingApproval?>(null);
        public Task<IReadOnlySet<string>> GetApprovedUrlsAsync(IReadOnlyCollection<string> urls, CancellationToken cancellationToken) => Task.FromResult<IReadOnlySet<string>>(new HashSet<string>());
        public Task<bool> DecideAsync(string id, string status, string reviewedBy, string? reviewNote, string? convertedText, int convertedLinks, CancellationToken cancellationToken) => Task.FromResult(false);
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
