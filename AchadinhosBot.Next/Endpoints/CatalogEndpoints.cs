using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Models;
using Microsoft.AspNetCore.Mvc;

namespace AchadinhosBot.Next.Endpoints;

public static class CatalogEndpoints
{
    public static void MapCatalogEndpoints(this RouteGroupBuilder api)
    {
        api.MapGet("/catalog/items", async ([FromQuery] string? q, [FromQuery] int? limit, [FromQuery] string? target, HttpContext context, [FromServices] ICatalogOfferStore catalogOfferStore, CancellationToken ct) =>
        {
            var catalogTarget = ResolveTarget(target, context.Request);
            return Results.Ok(new { items = await catalogOfferStore.ListAsync(q, limit ?? 200, ct, catalogTarget) });
        });
        api.MapGet("/catalog/items/{query}", async (string query, [FromQuery] string? target, HttpContext context, [FromServices] ICatalogOfferStore catalogOfferStore, CancellationToken ct) =>
        {
            var item = await catalogOfferStore.FindByCodeAsync(query, ct, ResolveTarget(target, context.Request));
            return item is null ? Results.NotFound() : Results.Ok(item);
        });
        api.MapGet("/catalog/link-audit", async ([FromQuery] string? target, HttpContext context, [FromServices] ICatalogOfferStore catalogOfferStore, CancellationToken ct) =>
        {
            var catalogTarget = ResolveTarget(target, context.Request);
            return Results.Ok(new { success = true, target = catalogTarget, result = await catalogOfferStore.AuditLinksAsync(ct, catalogTarget) });
        }).RequireAuthorization("AdminOnly");
        api.MapPost("/catalog/revalidate-links", async ([FromQuery] string? target, [FromServices] IAuditTrail audit, HttpContext context, [FromServices] ICatalogOfferStore catalogOfferStore, CancellationToken ct) =>
        {
            var catalogTarget = ResolveTarget(target, context.Request);
            var result = await catalogOfferStore.RevalidateLinksAsync(ct, catalogTarget);
            await audit.WriteAsync("catalog.links.revalidated", context.User.Identity?.Name ?? "unknown", result, ct);
            return Results.Ok(new { success = true, target = catalogTarget, result });
        }).RequireAuthorization("AdminOnly");
    }

    private static string ResolveTarget(string? requestedTarget, HttpRequest request)
        => string.IsNullOrWhiteSpace(requestedTarget) ? CatalogTargetResolver.Resolve(request) : CatalogTargets.Normalize(requestedTarget, CatalogTargets.Prod);
}
