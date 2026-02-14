using System.Net.Http.Headers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Media;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramImageDownloadService
{
    private static readonly TimeSpan MediaTtl = TimeSpan.FromHours(2);
    private const long MaxBytes = 8 * 1024 * 1024;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMediaStore _mediaStore;
    private readonly WebhookOptions _webhookOptions;
    private readonly ILogger<InstagramImageDownloadService> _logger;

    public InstagramImageDownloadService(
        IHttpClientFactory httpClientFactory,
        IMediaStore mediaStore,
        IOptions<WebhookOptions> webhookOptions,
        ILogger<InstagramImageDownloadService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _mediaStore = mediaStore;
        _webhookOptions = webhookOptions.Value;
        _logger = logger;
    }

    public async Task<List<string>> DownloadAsync(IEnumerable<string> imageUrls, CancellationToken ct)
    {
        var list = imageUrls?.Where(u => !string.IsNullOrWhiteSpace(u)).Distinct().ToList() ?? new List<string>();
        if (list.Count == 0)
        {
            return new List<string>();
        }

        var client = _httpClientFactory.CreateClient("default");
        var results = new List<string>();
        foreach (var url in list.Take(6))
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                continue;
            }

            try
            {
                using var response = await client.GetAsync(uri, ct);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var length = response.Content.Headers.ContentLength;
                if (length.HasValue && length.Value > MaxBytes)
                {
                    continue;
                }

                var mime = response.Content.Headers.ContentType?.MediaType;
                if (string.IsNullOrWhiteSpace(mime))
                {
                    mime = GuessMimeType(uri.AbsolutePath);
                }
                if (string.IsNullOrWhiteSpace(mime) || !mime.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var bytes = await response.Content.ReadAsByteArrayAsync(ct);
                if (bytes.Length == 0 || bytes.Length > MaxBytes)
                {
                    continue;
                }

                var id = _mediaStore.Add(bytes, mime, MediaTtl);
                var publicUrl = BuildPublicMediaUrl(id);
                if (!string.IsNullOrWhiteSpace(publicUrl))
                {
                    results.Add(publicUrl);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Falha ao baixar imagem para Instagram");
            }
        }

        return results;
    }

    private string BuildPublicMediaUrl(string id)
    {
        var baseUrl = _webhookOptions.PublicBaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            return string.Empty;
        }

        var url = baseUrl.TrimEnd('/') + $"/media/{id}";
        if (IsNgrok(url))
        {
            url += "?ngrok-skip-browser-warning=1";
        }
        return url;
    }

    private static bool IsNgrok(string url)
        => url.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) || url.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase);

    private static string? GuessMimeType(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".jpg" => "image/jpeg",
            ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".webp" => "image/webp",
            ".gif" => "image/gif",
            _ => "image/jpeg"
        };
    }
}
