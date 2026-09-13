using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Media;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Stores admin-uploaded public media; it never triggers delivery.</summary>
public static class MediaUploadEndpoints
{
    public static void MapMediaUploadEndpoints(this WebApplication app)
    {
        app.MapPost("/api/admin/media/upload", async (HttpRequest request, [FromServices] ISettingsStore settingsStore, [FromServices] IOptions<WebhookOptions> webhookOptions, [FromServices] IMediaStore mediaStore, CancellationToken ct) =>
        {
            if (!request.HasFormContentType) return Results.BadRequest(new { error = "Envie a imagem como multipart/form-data." });
            var form = await request.ReadFormAsync(ct);
            var file = form.Files.GetFile("file") ?? form.Files.FirstOrDefault();
            if (file is null || file.Length <= 0) return Results.BadRequest(new { error = "Nenhum arquivo de imagem foi enviado." });
            if (file.Length > 10_000_000) return Results.BadRequest(new { error = "Imagem muito grande. Use uma imagem abaixo de 10 MB." });
            var mimeType = string.IsNullOrWhiteSpace(file.ContentType) ? "image/jpeg" : file.ContentType.Trim();
            if (!mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase)) return Results.BadRequest(new { error = "O arquivo enviado precisa ser uma imagem." });
            await using var stream = new MemoryStream();
            await file.CopyToAsync(stream, ct);
            var bytes = stream.ToArray();
            if (bytes.Length == 0) return Results.BadRequest(new { error = "Imagem vazia." });
            var settings = await settingsStore.GetAsync(ct);
            var publicBaseUrl = PublicUrlResolver.Resolve(settings.BioHub?.PublicBaseUrl, webhookOptions.Value.PublicBaseUrl, request.Scheme, request.Host.ToString());
            if (string.IsNullOrWhiteSpace(publicBaseUrl) || PublicUrlResolver.IsInternalLikeHost(new Uri(publicBaseUrl).Host)) return Results.BadRequest(new { error = "Configure um dominio publico antes de carregar imagens." });
            var mediaId = mediaStore.Add(bytes, mimeType, TimeSpan.FromDays(365));
            return Results.Ok(new { success = true, mediaId, publicUrl = PublicUrlResolver.BuildMediaUrl(publicBaseUrl, mediaId), mimeType });
        }).RequireAuthorization("AdminOnly");
    }
}
