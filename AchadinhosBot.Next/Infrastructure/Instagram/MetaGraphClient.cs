using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class MetaGraphClient : IMetaGraphClient
{
    private readonly IHttpClientFactory _httpClientFactory;

    public MetaGraphClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<MetaGraphOperationResult> ValidateConfigurationAsync(InstagramPublishSettings settings, CancellationToken cancellationToken)
    {
        var configError = ValidateSettings(settings);
        if (configError is not null)
        {
            return new MetaGraphOperationResult(false, configError);
        }

        var client = _httpClientFactory.CreateClient("default");
        var baseUrl = ResolveBaseUrl(settings);

        var meUrl = $"{baseUrl}/{settings.InstagramUserId}?fields=id,username&access_token={Uri.EscapeDataString(settings.AccessToken!)}";
        using var meResponse = await client.GetAsync(meUrl, cancellationToken);
        var meBody = await meResponse.Content.ReadAsStringAsync(cancellationToken);
        if (!meResponse.IsSuccessStatusCode)
        {
            return BuildFailure(meBody);
        }

        var mediaUrl = $"{baseUrl}/{settings.InstagramUserId}/media?limit=1&access_token={Uri.EscapeDataString(settings.AccessToken!)}";
        using var mediaResponse = await client.GetAsync(mediaUrl, cancellationToken);
        var mediaBody = await mediaResponse.Content.ReadAsStringAsync(cancellationToken);
        return mediaResponse.IsSuccessStatusCode
            ? new MetaGraphOperationResult(true, RawResponse: mediaBody)
            : BuildFailure(mediaBody);
    }

    public async Task<MetaGraphOperationResult> GetMediaStatusAsync(InstagramPublishSettings settings, string mediaId, CancellationToken cancellationToken)
    {
        var configError = ValidateSettings(settings);
        if (configError is not null)
        {
            return new MetaGraphOperationResult(false, configError);
        }

        var client = _httpClientFactory.CreateClient("default");
        var url = $"{ResolveBaseUrl(settings)}/{mediaId}?fields=id,media_type,permalink,shortcode,timestamp&access_token={Uri.EscapeDataString(settings.AccessToken!)}";
        using var response = await client.GetAsync(url, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode
            ? new MetaGraphOperationResult(true, RawResponse: body)
            : BuildFailure(body);
    }

    public async Task<MetaGraphPublishResult> PublishAsync(InstagramPublishSettings settings, string postType, IReadOnlyList<string> mediaUrls, string caption, CancellationToken cancellationToken)
    {
        var configError = ValidateSettings(settings);
        if (configError is not null)
        {
            return new MetaGraphPublishResult(false, Error: configError);
        }

        try
        {
            if (mediaUrls.Count == 0)
            {
                return new MetaGraphPublishResult(false, Error: "Sem midia para publicar.");
            }

            var client = _httpClientFactory.CreateClient("default");
            var baseUrl = ResolveBaseUrl(settings);
            var normalizedType = InstagramWorkflowSupport.NormalizePostType(postType);
            var cleanUrls = mediaUrls.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).ToList();

            if (normalizedType == "story")
            {
                var firstMedia = cleanUrls.FirstOrDefault();
                if (string.IsNullOrWhiteSpace(firstMedia))
                {
                    return new MetaGraphPublishResult(false, Error: "Sem midia para publicar story.");
                }

                var isVideo = await IsLikelyVideoUrlAsync(client, firstMedia, cancellationToken);
                var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, firstMedia, string.Empty, false, "STORIES", isVideo, cancellationToken);
                if (string.IsNullOrWhiteSpace(containerId))
                {
                    return new MetaGraphPublishResult(false, Error: $"Falha ao criar story. {containerError}", IsTransient: IsTransientError(containerError));
                }

                var (mediaId, publishError) = await PublishMediaAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, containerId!, cancellationToken);
                return string.IsNullOrWhiteSpace(mediaId)
                    ? new MetaGraphPublishResult(false, Error: $"Falha ao publicar story. {publishError}", IsTransient: IsTransientError(publishError))
                    : new MetaGraphPublishResult(true, mediaId);
            }

            if (normalizedType == "reel")
            {
                var firstMedia = cleanUrls.FirstOrDefault();
                if (string.IsNullOrWhiteSpace(firstMedia))
                {
                    return new MetaGraphPublishResult(false, Error: "Sem midia para publicar reel.");
                }

                var isVideo = await IsLikelyVideoUrlAsync(client, firstMedia, cancellationToken);
                if (!isVideo)
                {
                    return new MetaGraphPublishResult(false, Error: "Reel requer URL de video valida.");
                }

                var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, firstMedia, caption, false, "REELS", true, cancellationToken);
                if (string.IsNullOrWhiteSpace(containerId))
                {
                    return new MetaGraphPublishResult(false, Error: $"Falha ao criar reel. {containerError}", IsTransient: IsTransientError(containerError));
                }

                var (mediaId, publishError) = await PublishMediaAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, containerId!, cancellationToken);
                return string.IsNullOrWhiteSpace(mediaId)
                    ? new MetaGraphPublishResult(false, Error: $"Falha ao publicar reel. {publishError}", IsTransient: IsTransientError(publishError))
                    : new MetaGraphPublishResult(true, mediaId);
            }

            if (cleanUrls.Count == 1)
            {
                var isVideo = await IsLikelyVideoUrlAsync(client, cleanUrls[0], cancellationToken);
                var mediaType = isVideo ? "VIDEO" : null;
                var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, cleanUrls[0], caption, false, mediaType, isVideo, cancellationToken);
                if (string.IsNullOrWhiteSpace(containerId))
                {
                    return new MetaGraphPublishResult(false, Error: $"Falha ao criar container. {containerError}", IsTransient: IsTransientError(containerError));
                }

                var (mediaId, publishError) = await PublishMediaAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, containerId!, cancellationToken);
                return string.IsNullOrWhiteSpace(mediaId)
                    ? new MetaGraphPublishResult(false, Error: $"Falha ao publicar. {publishError}", IsTransient: IsTransientError(publishError))
                    : new MetaGraphPublishResult(true, mediaId);
            }

            foreach (var candidate in cleanUrls)
            {
                if (await IsLikelyVideoUrlAsync(client, candidate, cancellationToken))
                {
                    return new MetaGraphPublishResult(false, Error: "Carrossel com video nao suportado neste fluxo automatico.");
                }
            }

            var childIds = new List<string>();
            string? firstError = null;
            foreach (var url in cleanUrls)
            {
                var (childId, childError) = await CreateMediaContainerAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, url, string.Empty, true, null, false, cancellationToken);
                if (!string.IsNullOrWhiteSpace(childId))
                {
                    childIds.Add(childId!);
                }

                if (firstError is null && !string.IsNullOrWhiteSpace(childError))
                {
                    firstError = childError;
                }
            }

            if (childIds.Count == 0)
            {
                return new MetaGraphPublishResult(false, Error: $"Falha ao criar itens do carrossel. {firstError}", IsTransient: IsTransientError(firstError));
            }

            var (parentId, parentError) = await CreateCarouselContainerAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, childIds, caption, cancellationToken);
            if (string.IsNullOrWhiteSpace(parentId))
            {
                return new MetaGraphPublishResult(false, Error: $"Falha ao criar carrossel. {parentError}", IsTransient: IsTransientError(parentError));
            }

            var (publishId, publishErrorCarousel) = await PublishMediaAsync(client, baseUrl, settings.InstagramUserId!, settings.AccessToken!, parentId!, cancellationToken);
            return string.IsNullOrWhiteSpace(publishId)
                ? new MetaGraphPublishResult(false, Error: $"Falha ao publicar carrossel. {publishErrorCarousel}", IsTransient: IsTransientError(publishErrorCarousel))
                : new MetaGraphPublishResult(true, publishId);
        }
        catch (Exception ex)
        {
            return new MetaGraphPublishResult(false, Error: ex.Message, IsTransient: true);
        }
    }

    public async Task<MetaGraphOperationResult> ReplyToCommentAsync(InstagramPublishSettings settings, string commentId, string message, CancellationToken cancellationToken)
    {
        var configError = ValidateSettings(settings);
        if (configError is not null)
        {
            return new MetaGraphOperationResult(false, configError);
        }

        var client = _httpClientFactory.CreateClient("default");
        var url = $"{ResolveBaseUrl(settings)}/{commentId}/replies";
        using var response = await client.PostAsync(url, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["message"] = message,
            ["access_token"] = settings.AccessToken!
        }), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode
            ? new MetaGraphOperationResult(true, RawResponse: body)
            : BuildFailure(body);
    }

    public async Task<MetaGraphOperationResult> SendDirectMessageAsync(InstagramPublishSettings settings, string recipientId, string message, CancellationToken cancellationToken)
    {
        var configError = ValidateSettings(settings);
        if (configError is not null)
        {
            return new MetaGraphOperationResult(false, configError);
        }

        var client = _httpClientFactory.CreateClient("default");
        var url = $"{ResolveBaseUrl(settings)}/{settings.InstagramUserId}/messages";
        using var response = await client.PostAsync(url, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["recipient"] = $"{{\"id\":\"{recipientId}\"}}",
            ["message"] = $"{{\"text\":\"{EscapeJsonValue(message)}\"}}",
            ["access_token"] = settings.AccessToken!
        }), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode
            ? new MetaGraphOperationResult(true, RawResponse: body)
            : BuildFailure(body);
    }

    private static MetaGraphOperationResult BuildFailure(string body)
    {
        var error = ExtractGraphError(body) ?? body;
        return new MetaGraphOperationResult(false, error, body, IsTransientError(error));
    }

    private static string ResolveBaseUrl(InstagramPublishSettings settings)
        => string.IsNullOrWhiteSpace(settings.GraphBaseUrl) ? "https://graph.facebook.com/v19.0" : settings.GraphBaseUrl.TrimEnd('/');

    private static string? ValidateSettings(InstagramPublishSettings settings)
    {
        if (!settings.Enabled)
        {
            return "Publicacao Instagram desativada.";
        }

        if (string.IsNullOrWhiteSpace(settings.AccessToken) || settings.AccessToken == "********")
        {
            return "Access token nao configurado.";
        }

        if (string.IsNullOrWhiteSpace(settings.InstagramUserId))
        {
            return "Instagram user id nao configurado.";
        }

        return null;
    }

    private static async Task<bool> IsLikelyVideoUrlAsync(HttpClient client, string url, CancellationToken cancellationToken)
    {
        var normalized = url.ToLowerInvariant();
        if (normalized.Contains(".mp4", StringComparison.Ordinal) ||
            normalized.Contains(".mov", StringComparison.Ordinal) ||
            normalized.Contains(".m4v", StringComparison.Ordinal) ||
            normalized.Contains(".webm", StringComparison.Ordinal) ||
            normalized.Contains(".m3u8", StringComparison.Ordinal))
        {
            return true;
        }

        try
        {
            using var headRequest = new HttpRequestMessage(HttpMethod.Head, url);
            using var headResponse = await client.SendAsync(headRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (headResponse.Content.Headers.ContentType?.MediaType?.StartsWith("video/", StringComparison.OrdinalIgnoreCase) == true)
            {
                return true;
            }
        }
        catch
        {
        }

        try
        {
            using var getRequest = new HttpRequestMessage(HttpMethod.Get, url);
            getRequest.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
            using var getResponse = await client.SendAsync(getRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return getResponse.Content.Headers.ContentType?.MediaType?.StartsWith("video/", StringComparison.OrdinalIgnoreCase) == true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<(string? Id, string? Error)> CreateMediaContainerAsync(HttpClient client, string baseUrl, string userId, string token, string mediaUrl, string caption, bool carouselItem, string? mediaType, bool isVideo, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string> { ["access_token"] = token };
        if (isVideo)
        {
            form["video_url"] = mediaUrl;
            if (string.IsNullOrWhiteSpace(mediaType))
            {
                form["media_type"] = "VIDEO";
            }
        }
        else
        {
            form["image_url"] = mediaUrl;
        }

        if (!string.IsNullOrWhiteSpace(mediaType))
        {
            form["media_type"] = mediaType;
        }

        if (!string.IsNullOrWhiteSpace(caption))
        {
            form["caption"] = caption;
        }

        if (carouselItem)
        {
            form["is_carousel_item"] = "true";
        }

        using var response = await client.PostAsync($"{baseUrl}/{userId}/media", new FormUrlEncodedContent(form), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode ? (TryGetIdFromJson(body), null) : (null, ExtractGraphError(body));
    }

    private static async Task<(string? Id, string? Error)> CreateCarouselContainerAsync(HttpClient client, string baseUrl, string userId, string token, List<string> children, string caption, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["access_token"] = token,
            ["media_type"] = "CAROUSEL",
            ["children"] = string.Join(",", children)
        };
        if (!string.IsNullOrWhiteSpace(caption))
        {
            form["caption"] = caption;
        }

        using var response = await client.PostAsync($"{baseUrl}/{userId}/media", new FormUrlEncodedContent(form), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode ? (TryGetIdFromJson(body), null) : (null, ExtractGraphError(body));
    }

    private static async Task<(string? Id, string? Error)> PublishMediaAsync(HttpClient client, string baseUrl, string userId, string token, string creationId, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["creation_id"] = creationId,
            ["access_token"] = token
        };

        string? lastError = null;
        foreach (var delay in new[] { 0, 4, 8, 12, 16, 22 })
        {
            if (delay > 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(delay), cancellationToken);
            }

            using var response = await client.PostAsync($"{baseUrl}/{userId}/media_publish", new FormUrlEncodedContent(form), cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return (TryGetIdFromJson(body), null);
            }

            lastError = ExtractGraphError(body) ?? body;
            if (!IsGraphMediaNotReadyError(body))
            {
                return (null, lastError);
            }
        }

        return (null, lastError ?? "Media ainda nao ficou pronta para publicacao.");
    }

    private static string? TryGetIdFromJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("id", out var idNode) && idNode.ValueKind == JsonValueKind.String
                ? idNode.GetString()
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractGraphError(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("error", out var error))
            {
                var msg = GetJsonValueAsString(error, "message");
                var code = GetJsonValueAsString(error, "code");
                var sub = GetJsonValueAsString(error, "error_subcode");
                return $"Graph error: {msg} (code {code}, sub {sub})";
            }
        }
        catch
        {
        }

        return json;
    }

    private static bool IsGraphMediaNotReadyError(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("error", out var error))
            {
                return false;
            }

            var code = GetJsonValueAsString(error, "code");
            var sub = GetJsonValueAsString(error, "error_subcode");
            if (string.Equals(code, "9007", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(sub, "2207027", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var message = GetJsonValueAsString(error, "message") ?? string.Empty;
            var userMessage = GetJsonValueAsString(error, "error_user_msg") ?? string.Empty;
            return message.Contains("not available", StringComparison.OrdinalIgnoreCase)
                   || message.Contains("not ready", StringComparison.OrdinalIgnoreCase)
                   || userMessage.Contains("nao esta pronta", StringComparison.OrdinalIgnoreCase)
                   || userMessage.Contains("aguarde", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string? GetJsonValueAsString(JsonElement node, string propertyName)
    {
        if (!node.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => value.ToString()
        };
    }

    private static bool IsTransientError(string? error)
    {
        if (string.IsNullOrWhiteSpace(error))
        {
            return false;
        }

        return error.Contains("rate", StringComparison.OrdinalIgnoreCase)
               || error.Contains("429", StringComparison.OrdinalIgnoreCase)
               || error.Contains("tempor", StringComparison.OrdinalIgnoreCase)
               || error.Contains("timeout", StringComparison.OrdinalIgnoreCase)
               || error.Contains("503", StringComparison.OrdinalIgnoreCase)
               || error.Contains("code 2", StringComparison.OrdinalIgnoreCase)
               || error.Contains("code 4", StringComparison.OrdinalIgnoreCase)
               || error.Contains("code 17", StringComparison.OrdinalIgnoreCase)
               || error.Contains("code 9007", StringComparison.OrdinalIgnoreCase);
    }

    private static string EscapeJsonValue(string value)
    {
        return (value ?? string.Empty)
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }
}
