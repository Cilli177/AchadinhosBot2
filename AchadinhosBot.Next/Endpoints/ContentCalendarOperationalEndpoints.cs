using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Infrastructure.Content;
using Microsoft.AspNetCore.Mvc;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Operational calendar actions. The due route only dispatches work; it never publishes inside HTTP.</summary>
public static class ContentCalendarOperationalEndpoints
{
    public static void MapContentCalendarOperationalEndpoints(this RouteGroupBuilder api)
    {
        api.MapPost("/content-calendar/import-reference", async (ContentReferenceImportRequest payload, [FromServices] ContentCalendarAutomationService automation, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(payload.ReferenceUrl) && string.IsNullOrWhiteSpace(payload.ReferenceCaption) && string.IsNullOrWhiteSpace(payload.OfferUrl))
                return Results.BadRequest(new { error = "Informe ao menos referencia (url/legenda) ou link da oferta." });

            return Results.Ok(new { success = true, item = await automation.ImportReferenceAsync(payload, ct) });
        }).RequireAuthorization("AdminOnly");

        api.MapPost("/content-calendar/process-due", async (HttpContext context, [FromServices] IContentCalendarDispatchService dispatcher, [FromServices] IAuditTrail audit, CancellationToken ct) =>
        {
            var actor = context.User.Identity?.Name ?? "admin";
            var dispatch = await dispatcher.QueueProcessDueAsync(actor, ct);
            await audit.WriteAsync("content_calendar.process_due.queued", actor, new { dispatch.MessageId, dispatch.Mode, dispatch.QueuedInOutbox }, ct);
            return Results.Accepted($"/content-calendar/process-due/{dispatch.MessageId}", new { success = true, queued = true, dispatch.MessageId, dispatch.Mode, dispatch.QueuedInOutbox });
        }).RequireAuthorization("AdminOnly");
    }
}
