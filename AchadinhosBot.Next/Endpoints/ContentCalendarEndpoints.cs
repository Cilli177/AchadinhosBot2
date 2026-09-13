using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Infrastructure.Content;
using Microsoft.AspNetCore.Mvc;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Administrative CRUD for editorial calendar records; processing due work remains separate.</summary>
public static class ContentCalendarEndpoints
{
    public static void MapContentCalendarEndpoints(this RouteGroupBuilder api)
    {
        api.MapGet("/content-calendar/items", async ([FromQuery] int? limit, [FromServices] IContentCalendarStore store, CancellationToken ct) =>
        {
            var items = (await store.ListAsync(ct)).OrderBy(x => x.ScheduledAt).Take(Math.Clamp(limit ?? 300, 1, 1000)).ToList();
            return Results.Ok(new { items });
        }).RequireAuthorization("ReadAccess");
        api.MapGet("/content-calendar/csv", async ([FromServices] IContentCalendarStore store, CancellationToken ct) =>
            Results.File(Encoding.UTF8.GetBytes(await store.ExportCsvAsync(ct)), "text/csv; charset=utf-8", "content-calendar.csv")).RequireAuthorization("AdminOnly");
        api.MapPost("/content-calendar/items", async (ContentCalendarCreateRequest payload, [FromServices] ContentCalendarAutomationService automationService, CancellationToken ct) =>
            Results.Ok(new { success = true, item = await automationService.CreateAsync(payload, ct) })).RequireAuthorization("AdminOnly");
        api.MapPut("/content-calendar/items/{id}", async (string id, ContentCalendarCreateRequest payload, [FromServices] IContentCalendarStore store, CancellationToken ct) =>
        {
            var item = await store.GetAsync(id, ct);
            if (item is null) return Results.NotFound(new { error = "Item do calendario nao encontrado." });
            item.ScheduledAt = payload.ScheduledAt ?? item.ScheduledAt; item.PostType = string.IsNullOrWhiteSpace(payload.PostType) ? item.PostType : payload.PostType.Trim(); item.SourceInput = payload.SourceInput ?? item.SourceInput; item.OfferContext = payload.OfferContext ?? item.OfferContext; item.MediaUrl = payload.MediaUrl ?? item.MediaUrl; item.OfferUrl = payload.OfferUrl ?? item.OfferUrl; item.Keyword = payload.Keyword ?? item.Keyword; item.Hashtags = payload.Hashtags ?? item.Hashtags; item.GeneratedCaption = payload.GeneratedCaption ?? item.GeneratedCaption; item.AutoPublish = payload.AutoPublish ?? item.AutoPublish; item.ReferenceUrl = payload.ReferenceUrl ?? item.ReferenceUrl; item.ReferenceCaption = payload.ReferenceCaption ?? item.ReferenceCaption; item.ReferenceMediaUrl = payload.ReferenceMediaUrl ?? item.ReferenceMediaUrl; item.UpdatedAt = DateTimeOffset.UtcNow;
            await store.SaveAsync(item, ct);
            return Results.Ok(new { success = true, item });
        }).RequireAuthorization("AdminOnly");
        api.MapDelete("/content-calendar/items/{id}", async (string id, [FromServices] IContentCalendarStore store, CancellationToken ct) => { await store.DeleteAsync(id, ct); return Results.Ok(new { success = true }); }).RequireAuthorization("AdminOnly");
    }
}
