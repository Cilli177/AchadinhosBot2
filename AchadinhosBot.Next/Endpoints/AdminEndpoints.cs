using System.Text.RegularExpressions;
using System.Security.Claims;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>
/// Admin endpoints for the conversor admin panel.
/// Routes accept an authenticated session (admin/operator) or the legacy X-Admin-Key header.
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

        // --- Generate AI Hashtags ---
        app.MapPost("/api/admin/generate-hashtags", async (
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
            var hashtags = await composer.SuggestHashtagsAsync(req.ProductName, settings.InstagramPosts, ct);

            return Results.Ok(new { success = true, hashtags });
        });

        // --- Upload Media ---
        app.MapPost("/api/admin/upload-media", async (
            HttpContext context,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            if (!context.Request.HasFormContentType)
                return Results.BadRequest("Form content expected.");

            IFormCollection form;
            try
            {
                form = await context.Request.ReadFormAsync(ct);
            }
            catch (BadHttpRequestException ex) when (ex.Message.Contains("Request body too large", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(new
                {
                    success = false,
                    error = "Arquivo acima do limite de upload. O ambiente agora aceita ate 256 MB; tente reenviar o video."
                }, statusCode: StatusCodes.Status413PayloadTooLarge);
            }

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
            await audit.WriteAsync("admin.upload_media", ResolveActor(context), new
            {
                file = file.FileName,
                storedAs = fileName,
                size = file.Length,
                contentType = file.ContentType
            }, ct);
            return Results.Ok(new { success = true, url });
        });

        // --- Create Instagram Draft ---
        app.MapPost("/api/admin/create-draft", async (
            AdminCreateDraftRequest req,
            HttpContext context,
            IInstagramPublishStore store,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = new InstagramPublishDraft
            {
                ProductName = req.ProductName,
                PostType = req.PostType ?? "feed",
                VideoUrl = req.VideoUrl,
                VideoCoverUrl = req.VideoCoverUrl,
                VideoCoverAtSeconds = req.VideoCoverAtSeconds,
                VideoMusicCue = req.VideoMusicCue,
                VideoTrimStartSeconds = req.VideoTrimStartSeconds,
                VideoTrimEndSeconds = req.VideoTrimEndSeconds,
                MusicTrackUrl = req.MusicTrackUrl,
                MusicStartSeconds = req.MusicStartSeconds,
                MusicEndSeconds = req.MusicEndSeconds,
                MusicVolume = req.MusicVolume,
                OriginalAudioVolume = req.OriginalAudioVolume,
                Caption = req.Caption,
                ImageUrls = req.ImageUrls ?? new(),
                Ctas = BuildDraftCtas(req.Caption, req.AutoReplyKeyword, req.AutoReplyLink),
                AutoReplyEnabled = req.AutoReplyEnabled,
                AutoReplyKeyword = req.AutoReplyKeyword,
                AutoReplyMessage = req.AutoReplyMessage,
                AutoReplyLink = req.AutoReplyLink,
                ScheduledFor = req.ScheduledFor,
                Status = req.ScheduledFor.HasValue ? "scheduled" : "draft"
            };
            ApplyCatalogIntent(draft, req.SendToCatalog, req.CatalogTarget);

            await store.SaveAsync(draft, ct);
            await audit.WriteAsync("admin.draft.created", ResolveActor(context), new
            {
                draftId = draft.Id,
                draft.ProductName,
                draft.PostType,
                draft.VideoCoverUrl,
                draft.VideoCoverAtSeconds,
                draft.VideoTrimStartSeconds,
                draft.VideoTrimEndSeconds,
                draft.MusicTrackUrl,
                draft.SendToCatalog,
                draft.CatalogTarget
            }, ct);
            return Results.Ok(new { success = true, draftId = draft.Id });
        });

        // --- Publish to Instagram ---
        app.MapPost("/api/admin/publish-instagram", async (
            AdminPublishRequest req,
            HttpContext context,
            IInstagramPublishStore draftStore,
            IInstagramPublishService publishService,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = await draftStore.GetAsync(req.DraftId, ct);
            if (draft is null)
                return Results.NotFound(new { success = false, error = "Draft not found." });

            if (req.SendToCatalog || !string.IsNullOrWhiteSpace(req.CatalogTarget))
            {
                var previousCatalogTarget = draft.CatalogTarget;
                var previousSendToCatalog = draft.SendToCatalog;
                ApplyCatalogIntent(draft, req.SendToCatalog, req.CatalogTarget);
                if (!string.Equals(previousCatalogTarget, draft.CatalogTarget, StringComparison.OrdinalIgnoreCase) ||
                    previousSendToCatalog != draft.SendToCatalog)
                {
                    await draftStore.UpdateAsync(draft, ct);
                }
            }

            var result = await publishService.QueuePublishAsync(req.DraftId, "admin_panel", ct);
            await audit.WriteAsync("admin.publish.instagram", ResolveActor(context), new
            {
                req.DraftId,
                accepted = result.Accepted,
                result.Mode,
                result.MessageId,
                result.Error,
                draft.CatalogTarget
            }, ct);
            return Results.Ok(new
            {
                success = result.Accepted,
                mode = result.Mode,
                messageId = result.MessageId,
                error = result.Error
            });
        });

        app.MapPost("/api/admin/publish-instagram-now", async (
            AdminPublishRequest req,
            HttpContext context,
            IInstagramPublishStore draftStore,
            IInstagramPublishService publishService,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = await draftStore.GetAsync(req.DraftId, ct);
            if (draft is null)
                return Results.NotFound(new { success = false, error = "Draft not found." });

            if (req.SendToCatalog || !string.IsNullOrWhiteSpace(req.CatalogTarget))
            {
                var previousCatalogTarget = draft.CatalogTarget;
                var previousSendToCatalog = draft.SendToCatalog;
                ApplyCatalogIntent(draft, req.SendToCatalog, req.CatalogTarget);
                if (!string.Equals(previousCatalogTarget, draft.CatalogTarget, StringComparison.OrdinalIgnoreCase) ||
                    previousSendToCatalog != draft.SendToCatalog)
                {
                    await draftStore.UpdateAsync(draft, ct);
                }
            }

            var result = await publishService.ExecutePublishAsync(req.DraftId, ct);
            await audit.WriteAsync("admin.publish.instagram_now", ResolveActor(context), new
            {
                req.DraftId,
                result.Success,
                result.StatusCode,
                result.MediaId,
                result.Error,
                draft.CatalogTarget
            }, ct);

            return Results.Ok(new
            {
                success = result.Success,
                statusCode = result.StatusCode,
                mediaId = result.MediaId,
                error = result.Error,
                draftId = result.DraftId
            });
        });

        // --- Publish to WhatsApp ---
        app.MapPost("/api/admin/publish-whatsapp", async (
            AdminPublishToChannelRequest req,
            HttpContext context,
            IWhatsAppGateway whatsapp,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
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

            await audit.WriteAsync("admin.publish.whatsapp", ResolveActor(context), new
            {
                req.TargetId,
                result.Success,
                result.Message
            }, ct);
            return Results.Ok(new { success = result.Success, message = result.Message });
        });

        // --- Publish to Telegram ---
        app.MapPost("/api/admin/publish-telegram", async (
            AdminPublishToChannelRequest req,
            HttpContext context,
            ITelegramGateway telegram,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            try
            {
                var chatId = long.Parse(req.TargetId);
                var result = !string.IsNullOrWhiteSpace(req.ImageUrl)
                    ? await telegram.SendPhotoAsync(null, chatId, req.ImageUrl, req.Content, ct)
                    : await telegram.SendTextAsync(null, chatId, req.Content, ct);
                await audit.WriteAsync("admin.publish.telegram", ResolveActor(context), new
                {
                    chatId,
                    result.Success,
                    result.Message
                }, ct);
                return Results.Ok(new { success = result.Success, message = result.Message });
            }
            catch (Exception ex)
            {
                return Results.Json(new { success = false, error = ex.Message }, statusCode: 500);
            }
        });

        // --- Master Publish (Omnichannel) ---
        app.MapPost("/api/admin/publish-master", async (
            AdminMasterPublishRequest req,
            HttpContext context,
            IInstagramPublishService publishService,
            IWhatsAppGateway whatsapp,
            ITelegramGateway telegram,
            IInstagramPublishStore draftStore,
            ICatalogOfferStore catalogStore,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = await draftStore.GetAsync(req.DraftId, ct);
            if (draft == null && req.PublishInstagram)
                return Results.NotFound(new { success = false, error = "Draft not found." });

            if (draft is not null && (req.PublishCatalog || !string.IsNullOrWhiteSpace(req.CatalogTarget)))
            {
                ApplyCatalogIntent(draft, req.PublishCatalog, req.CatalogTarget);
                await draftStore.UpdateAsync(draft, ct);
            }

            var content = req.Content ?? draft?.Caption ?? string.Empty;
            var imageUrl = req.ImageUrl ?? draft?.ImageUrls.FirstOrDefault();

            var results = new Dictionary<string, object>();
            var allSucceeded = true;

            if (req.PublishTelegram && !string.IsNullOrWhiteSpace(req.TelegramChatId))
            {
                try
                {
                    var chatId = long.Parse(req.TelegramChatId);
                    var tgResult = !string.IsNullOrWhiteSpace(imageUrl)
                        ? await telegram.SendPhotoAsync(null, chatId, imageUrl, content, ct)
                        : await telegram.SendTextAsync(null, chatId, content, ct);
                    results["telegram"] = new { success = tgResult.Success, message = tgResult.Message };
                    allSucceeded &= tgResult.Success;
                }
                catch (Exception ex)
                {
                    results["telegram"] = new { success = false, error = ex.Message };
                    allSucceeded = false;
                }
            }

            if (req.PublishWhatsApp && !string.IsNullOrWhiteSpace(req.WhatsAppTargetId))
            {
                try
                {
                    WhatsAppSendResult waResult;
                    if (!string.IsNullOrWhiteSpace(imageUrl))
                    {
                        waResult = await whatsapp.SendImageUrlAsync(null, req.WhatsAppTargetId, imageUrl, content, null, "card.jpg", ct);
                    }
                    else
                    {
                        waResult = await whatsapp.SendTextAsync(null, req.WhatsAppTargetId, content, ct);
                    }
                    results["whatsapp"] = new { success = waResult.Success, error = waResult.Message };
                    allSucceeded &= waResult.Success;
                }
                catch (Exception ex)
                {
                    results["whatsapp"] = new { success = false, error = ex.Message };
                    allSucceeded = false;
                }
            }

            if (req.PublishInstagram)
            {
                try
                {
                    var igResult = await publishService.QueuePublishAsync(req.DraftId, "admin_master", ct);
                    results["instagram"] = new
                    {
                        success = igResult.Accepted,
                        mode = igResult.Mode,
                        messageId = igResult.MessageId,
                        persistedLocally = igResult.PersistedLocally,
                        error = igResult.Error
                    };
                    allSucceeded &= igResult.Accepted;
                }
                catch (Exception ex)
                {
                    results["instagram"] = new { success = false, error = ex.Message };
                    allSucceeded = false;
                }
            }

            if (req.PublishCatalog)
            {
                try
                {
                    if (draft != null && string.Equals(draft.Status, "published", StringComparison.OrdinalIgnoreCase))
                    {
                        var syncResult = await catalogStore.SyncFromPublishedDraftsAsync(new[] { draft }, ct);
                        results["catalog"] = new
                        {
                            success = true,
                            itemsUpdated = syncResult.Updated + syncResult.Created,
                            target = CatalogTargets.ResolveDraftTarget(draft)
                        };
                    }
                    else if (draft != null)
                    {
                        results["catalog"] = new
                        {
                            success = true,
                            scheduled = true,
                            target = CatalogTargets.ResolveDraftTarget(draft),
                            message = "Catalogo sera sincronizado apos a publicacao do draft."
                        };
                    }
                    else
                    {
                        results["catalog"] = new { success = false, error = "Draft object required for catalog." };
                        allSucceeded = false;
                    }
                }
                catch (Exception ex)
                {
                    results["catalog"] = new { success = false, error = ex.Message };
                    allSucceeded = false;
                }
            }

            await audit.WriteAsync("admin.publish.master", ResolveActor(context), new
            {
                req.DraftId,
                req.PublishInstagram,
                req.PublishTelegram,
                req.PublishWhatsApp,
                req.PublishCatalog,
                req.TelegramChatId,
                req.WhatsAppTargetId,
                catalogTarget = draft?.CatalogTarget ?? req.CatalogTarget,
                success = allSucceeded
            }, ct);
            return Results.Ok(new { success = allSucceeded, channels = results });
        });

        // --- Add to Catalog ---
        app.MapPost("/api/admin/add-to-catalog", async (
            AdminAddToCatalogRequest req,
            HttpContext context,
            ICatalogOfferStore catalogStore,
            IInstagramPublishStore draftStore,
            IOptions<WebhookOptions> opts,
            IAuditTrail audit,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = await draftStore.GetAsync(req.DraftId, ct);
            if (draft == null) return Results.NotFound("Draft not found.");

            var previousCatalogTarget = draft.CatalogTarget;
            var previousSendToCatalog = draft.SendToCatalog;
            ApplyCatalogIntent(draft, true, req.CatalogTarget);
            if (!string.Equals(previousCatalogTarget, draft.CatalogTarget, StringComparison.OrdinalIgnoreCase) ||
                previousSendToCatalog != draft.SendToCatalog)
            {
                await draftStore.UpdateAsync(draft, ct);
            }

            if (!string.Equals(draft.Status, "published", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Ok(new
                {
                    success = true,
                    scheduled = true,
                    target = CatalogTargets.ResolveDraftTarget(draft),
                    message = "Draft marcado para sincronizar no catalogo apos a publicacao."
                });
            }

            var syncResult = await catalogStore.SyncFromPublishedDraftsAsync(new[] { draft }, ct);
            await audit.WriteAsync("admin.catalog.sync_single", ResolveActor(context), new
            {
                req.DraftId,
                draft.CatalogTarget,
                itemsUpdated = syncResult.Created + syncResult.Updated
            }, ct);
            return Results.Ok(new
            {
                success = true,
                target = CatalogTargets.ResolveDraftTarget(draft),
                itemsUpdated = syncResult.Created + syncResult.Updated
            });
        });

        app.MapGet("/api/admin/analytics/summary", async (
            HttpContext context,
            IOperationalAnalyticsService analyticsService,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var hoursRaw = context.Request.Query["hours"].ToString();
            var hours = int.TryParse(hoursRaw, out var parsedHours) ? parsedHours : 168;
            var summary = await analyticsService.GetSummaryAsync(hours, ct);
            return Results.Ok(new { success = true, summary });
        });

        // --- List Drafts ---
        app.MapGet("/api/admin/drafts", async (
            HttpContext context,
            IInstagramPublishStore store,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var drafts = await store.ListAsync(ct);
            var result = drafts.OrderByDescending(d => d.CreatedAt).Take(50).Select(d => new
            {
                id = d.Id,
                productName = d.ProductName,
                postType = d.PostType,
                status = d.Status,
                mediaId = d.MediaId,
                catalogTarget = CatalogTargets.ResolveDraftTarget(d),
                createdAt = d.CreatedAt,
                imageUrl = d.ImageUrls.FirstOrDefault()
            });

            return Results.Ok(new { success = true, drafts = result });
        });

        // --- Get Specific Draft ---
        app.MapGet("/api/admin/draft/{draftId}", async (
            string draftId,
            HttpContext context,
            IInstagramPublishStore store,
            IOptions<WebhookOptions> opts,
            CancellationToken ct) =>
        {
            if (!IsAdminAuthorized(context, opts.Value.ApiKey))
                return Results.Json(new { success = false, error = "Acesso negado." }, statusCode: 403);

            var draft = await store.GetAsync(draftId, ct);
            if (draft == null) return Results.NotFound("Draft not found.");

            return Results.Ok(new { success = true, draft });
        });
    }

    private static bool IsAdminAuthorized(HttpContext ctx, string apiKey)
    {
        if (ctx.User.Identity?.IsAuthenticated == true)
        {
            var role = ctx.User.FindFirst(ClaimTypes.Role)?.Value;
            if (string.Equals(role, "admin", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(role, "operator", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (ctx.Request.Headers.TryGetValue("X-Admin-Key", out var provided))
            return !string.IsNullOrWhiteSpace(provided.ToString()) &&
                   SecretComparer.EqualsConstantTime(apiKey, provided.ToString());
        return false;
    }

    private static string ResolveActor(HttpContext ctx)
    {
        if (!string.IsNullOrWhiteSpace(ctx.User.Identity?.Name))
        {
            return ctx.User.Identity!.Name!;
        }

        if (ctx.Request.Headers.TryGetValue("X-Admin-Key", out var provided) &&
            !string.IsNullOrWhiteSpace(provided.ToString()))
        {
            return "api_key";
        }

        return "anonymous";
    }

    private static void ApplyCatalogIntent(InstagramPublishDraft draft, bool sendToCatalog, string? catalogTarget)
    {
        var resolved = CatalogTargets.ResolveConfiguredTarget(
            catalogTarget,
            sendToCatalog,
            CatalogTargets.Prod);

        draft.CatalogTarget = resolved;
        draft.SendToCatalog = CatalogTargets.IsEnabled(resolved);
        draft.CatalogIntentLocked = true;
    }

    private static List<InstagramCtaOption> BuildDraftCtas(string? caption, string? rawKeywords, string? preferredLink)
    {
        var keywords = Regex.Split(rawKeywords ?? string.Empty, @"[\s,;|/]+", RegexOptions.CultureInvariant)
            .Select(x => x.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => Regex.Replace(x.ToUpperInvariant(), @"[^A-Z0-9À-ÖØ-Þ]+", string.Empty, RegexOptions.CultureInvariant))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();

        var link = !string.IsNullOrWhiteSpace(preferredLink)
            ? preferredLink.Trim()
            : Regex.Match(caption ?? string.Empty, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant).Value.Trim();

        if (keywords.Count == 0 || string.IsNullOrWhiteSpace(link))
        {
            return new List<InstagramCtaOption>();
        }

        return keywords
            .Select(keyword => new InstagramCtaOption
            {
                Keyword = keyword,
                Link = link
            })
            .ToList();
    }
}

// --- Request DTOs ---

public sealed record AdminGenerateCardRequest(string Title, string? Price, string? PreviousPrice, int? DiscountPercent, string ImageUrl);
public sealed record AdminGenerateCaptionRequest(string ProductName, string? OfferContext);
public sealed record AdminCreateDraftRequest(string ProductName, string? PostType, string Caption, List<string>? ImageUrls, string? VideoUrl, string? VideoCoverUrl, double? VideoCoverAtSeconds, string? VideoMusicCue, double? VideoTrimStartSeconds, double? VideoTrimEndSeconds, string? MusicTrackUrl, double? MusicStartSeconds, double? MusicEndSeconds, double? MusicVolume, double? OriginalAudioVolume, bool AutoReplyEnabled, string? AutoReplyKeyword, string? AutoReplyMessage, string? AutoReplyLink, DateTimeOffset? ScheduledFor, bool SendToCatalog = false, string? CatalogTarget = null);
public sealed record AdminPublishRequest(string DraftId, bool SendToCatalog = false, string? CatalogTarget = null);
public sealed record AdminPublishToChannelRequest(string TargetId, string Content, string? ImageUrl);
public sealed record AdminMasterPublishRequest(string DraftId, bool PublishInstagram, bool PublishTelegram, bool PublishWhatsApp, bool PublishCatalog, string? TelegramChatId, string? WhatsAppTargetId, string? Content, string? ImageUrl, string? CatalogTarget = null);
public sealed record AdminAddToCatalogRequest(string DraftId, string? CatalogTarget = null);
