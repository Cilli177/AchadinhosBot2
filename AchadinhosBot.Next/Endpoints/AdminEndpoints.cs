using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>
/// Admin-only endpoints for the conversor admin panel.
/// All routes are protected by X-Admin-Key header, which must match WebhookOptions.ApiKey.
/// </summary>
public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this WebApplication app)
    {
        // --- Serve conversor-admin.html ---
        app.MapGet("/conversor-admin", (HttpContext context) =>
        {
            var path = Path.Combine(AppContext.BaseDirectory, "wwwroot", "conversor-admin.html");
            return File.Exists(path) ? Results.File(path, "text/html") : Results.NotFound();
        });

        // --- Validate admin key (used by login gate) ---
        app.MapGet("/api/admin/validate-key", (HttpContext context, IOptions<WebhookOptions> opts) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { valid = false }, statusCode: 403);
            return Results.Ok(new { valid = true });
        });

        // --- Generate Card (formerly publish-instagram, now specialized) ---
        app.MapPost("/api/admin/generate-card", async (
            AdminGenerateCardRequest req,
            HttpContext context,
            IPromotionalCardGenerator cardGenerator,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var cardBytes = await cardGenerator.GenerateCardAsync(
                productName: req.Title,
                currentPrice: req.Price ?? "Preço sob consulta",
                previousPrice: req.PreviousPrice,
                discountPercent: req.DiscountPercent.HasValue ? $"{req.DiscountPercent}% OFF" : null,
                imageUrl: req.ImageUrl,
                cancellationToken: ct);

            if (cardBytes is null || cardBytes.Length == 0)
                return Results.Json(new { success = false, error = "Falha ao gerar card VIP." }, statusCode: 500);

            return Results.Ok(new { success = true, cardBase64 = Convert.ToBase64String(cardBytes) });
        });

        // --- Generate AI Caption ---
        app.MapPost("/api/admin/generate-caption", async (
            AdminGenerateCaptionRequest req,
            HttpContext context,
            IInstagramPostComposer composer,
            ISettingsStore settingsStore,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var settings = await settingsStore.GetAsync(ct);
            var caption = await composer.BuildAsync(req.ProductName, req.OfferContext, settings.InstagramPosts, ct);

            return Results.Ok(new { success = true, caption });
        });

        // --- Upload Media ---
        app.MapPost("/api/admin/upload-media", async (
            HttpContext context,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            if (!context.Request.HasFormContentType)
                return Results.BadRequest("Form content expected.");

            var form = await context.Request.ReadFormAsync(ct);
            var file = form.Files.GetFile("file");
            if (file == null) return Results.BadRequest("No file uploaded.");

            var mediaDir = Path.Combine(AppContext.BaseDirectory, "wwwroot", "media", "admin");
            if (!Directory.Exists(mediaDir)) Directory.CreateDirectory(mediaDir);

            var fileName = $"{Guid.NewGuid():N}{Path.GetExtension(file.FileName)}";
            var filePath = Path.Combine(mediaDir, fileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream, ct);
            }

            var url = $"/media/admin/{fileName}";
            return Results.Ok(new { success = true, url });
        });

        // --- Create Instagram Draft ---
        app.MapPost("/api/admin/create-draft", async (
            AdminCreateDraftRequest req,
            HttpContext context,
            IInstagramPublishStore store,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = new InstagramPublishDraft
            {
                ProductName = req.ProductName,
                PostType = req.PostType ?? "feed",
                Caption = req.Caption,
                ImageUrls = req.ImageUrls ?? new(),
                AutoReplyEnabled = req.AutoReplyEnabled,
                Status = "draft"
            };

            await store.SaveAsync(draft, ct);
            return Results.Ok(new { success = true, draftId = draft.Id });
        });

        // --- Publish to Instagram ---
        app.MapPost("/api/admin/publish-instagram", async (
            AdminPublishRequest req,
            HttpContext context,
            IInstagramPublishService publishService,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var result = await publishService.ExecutePublishAsync(req.DraftId, ct);
            return Results.Ok(new
            {
                success = result.Success,
                mediaId = result.MediaId,
                error = result.Error
            });
        });

        // --- Publish to WhatsApp ---
        app.MapPost("/api/admin/publish-whatsapp", async (
            AdminPublishToChannelRequest req,
            HttpContext context,
            IWhatsAppGateway whatsapp,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            WhatsAppSendResult result;
            if (!string.IsNullOrWhiteSpace(req.ImageUrl))
            {
                result = await whatsapp.SendImageUrlAsync(null, req.TargetId, req.ImageUrl, req.Content, null, "card.jpg", ct);
            }
            else
            {
                result = await whatsapp.SendTextAsync(null, req.TargetId, req.Content, ct);
            }

            return Results.Ok(new { success = result.Success, message = result.Message });
        });

        // --- Publish to Telegram ---
        app.MapPost("/api/admin/publish-telegram", async (
            AdminPublishToChannelRequest req,
            HttpContext context,
            ITelegramOutboundPublisher telegram,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            try
            {
                var chatId = long.Parse(req.TargetId);
                var cmd = new SendTelegramMessageCommand
                {
                    ChatId = chatId,
                    Text = req.Content,
                    ImageUrl = req.ImageUrl
                };
                await telegram.PublishAsync(cmd, ct);
                return Results.Ok(new { success = true });
            }
            catch (Exception ex)
            {
                return Results.Json(new { success = false, error = ex.Message }, statusCode: 500);
            }
        });

        // --- Add to Catalog ---
        app.MapPost("/api/admin/add-to-catalog", async (
            AdminAddToCatalogRequest req,
            HttpContext context,
            ICatalogOfferStore catalogStore,
            IInstagramPublishStore draftStore,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = await draftStore.GetAsync(req.DraftId, ct);
            if (draft == null) return Results.NotFound("Draft not found.");

            await catalogStore.SyncFromPublishedDraftsAsync(new[] { draft }, ct);
            return Results.Ok(new { success = true });
        });
    }

    private static bool IsAdminAuthorized(HttpContext ctx, string apiKey)
    {
        if (ctx.Request.Headers.TryGetValue("X-Admin-Key", out var provided))
            return SecretComparer.EqualsConstantTime(apiKey, provided.ToString());
        return false;
    }
}

// --- Request DTOs ---

public sealed record AdminGenerateCardRequest(string Title, string? Price, string? PreviousPrice, int? DiscountPercent, string ImageUrl);
public sealed record AdminGenerateCaptionRequest(string ProductName, string? OfferContext);
public sealed record AdminCreateDraftRequest(string ProductName, string? PostType, string Caption, List<string>? ImageUrls, bool AutoReplyEnabled);
public sealed record AdminPublishRequest(string DraftId);
public sealed record AdminPublishToChannelRequest(string TargetId, string Content, string? ImageUrl);
public sealed record AdminAddToCatalogRequest(string DraftId);
