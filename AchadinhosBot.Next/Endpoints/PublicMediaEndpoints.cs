namespace AchadinhosBot.Next.Endpoints;

public static class PublicMediaEndpoints
{
    public static void MapPublicMediaEndpoints(this WebApplication app)
    {
        app.MapGet("/media/remote", async (
            string url,
            IHttpClientFactory httpClientFactory,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(url) ||
                !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                return Results.BadRequest("URL invalida.");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (compatible; ReiDasOfertasBot/1.0)");
            request.Headers.Referrer = new Uri($"{context.Request.Scheme}://{context.Request.Host}");

            var client = httpClientFactory.CreateClient();
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                return Results.StatusCode((int)response.StatusCode);
            }

            var contentType = response.Content.Headers.ContentType?.MediaType;
            if (string.IsNullOrWhiteSpace(contentType) || !contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest("Midia remota invalida.");
            }

            var bytes = await response.Content.ReadAsByteArrayAsync(ct);
            context.Response.Headers.CacheControl = "public,max-age=1800";
            return Results.File(bytes, contentType);
        });
    }
}
