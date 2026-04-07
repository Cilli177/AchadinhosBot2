using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Governance;
using AchadinhosBot.Next.Domain.Models;
using Microsoft.AspNetCore.Mvc;

namespace AchadinhosBot.Next.Endpoints;

public static class GovernanceAdminEndpointsExtensions
{
    public static void MapGovernanceAdminEndpoints(this WebApplication app)
    {
        var admin = app.MapGroup("/api/admin").RequireAuthorization("AdminOnly");

        admin.MapGet("/governance/status", async (IGovernanceEventStore store, CancellationToken ct) =>
        {
            var status = await store.GetStatusSnapshotAsync(ct);
            return Results.Ok(status);
        });

        admin.MapGet("/governance/incidents", async (
            IGovernanceEventStore store,
            [FromQuery] bool onlyOpen,
            [FromQuery] int limit,
            CancellationToken ct) =>
        {
            var incidents = await store.ListIncidentsAsync(onlyOpen, limit <= 0 ? 100 : limit, ct);
            return Results.Ok(incidents);
        });

        admin.MapGet("/governance/actions", async (
            IGovernanceEventStore store,
            [FromQuery] int limit,
            CancellationToken ct) =>
        {
            var actions = await store.ListActionsAsync(limit <= 0 ? 100 : limit, ct);
            return Results.Ok(actions);
        });

        admin.MapGet("/governance/tuning", async (
            IGovernanceEventStore store,
            [FromQuery] int limit,
            CancellationToken ct) =>
        {
            var tuning = await store.ListTuningChangesAsync(limit <= 0 ? 100 : limit, ct);
            return Results.Ok(tuning);
        });

        admin.MapGet("/settings/versions", async (
            ISettingsStore settingsStore,
            [FromQuery] int limit,
            CancellationToken ct) =>
        {
            var versions = await settingsStore.ListVersionsAsync(limit <= 0 ? 50 : limit, ct);
            var current = await settingsStore.GetCurrentVersionAsync(ct);
            return Results.Ok(new { current, versions });
        });

        admin.MapPost("/settings/restore", async (
            ISettingsStore settingsStore,
            RestoreVersionRequest request,
            CancellationToken ct) =>
        {
            await settingsStore.RestoreVersionAsync(request.VersionId, ct);
            return Results.Ok(new { success = true, restoredVersion = request.VersionId });
        });

        admin.MapGet("/catalog/versions", async (
            ICatalogOfferStore catalogStore,
            [FromQuery] string? catalogTarget,
            [FromQuery] int limit,
            CancellationToken ct) =>
        {
            var target = string.IsNullOrWhiteSpace(catalogTarget) ? CatalogTargets.Prod : catalogTarget!;
            var versions = await catalogStore.ListVersionsAsync(target, limit <= 0 ? 50 : limit, ct);
            var current = await catalogStore.GetCurrentVersionAsync(target, ct);
            return Results.Ok(new { target, current, versions });
        });

        admin.MapPost("/catalog/restore", async (
            ICatalogOfferStore catalogStore,
            RestoreCatalogVersionRequest request,
            CancellationToken ct) =>
        {
            await catalogStore.RestoreVersionAsync(request.CatalogTarget, request.VersionId, ct);
            return Results.Ok(new { success = true, request.CatalogTarget, restoredVersion = request.VersionId });
        });

        admin.MapGet("/canary/rules", async (ICanaryRuleStore canaryRuleStore, CancellationToken ct) =>
        {
            var rules = await canaryRuleStore.ListAsync(ct);
            return Results.Ok(rules);
        });

        admin.MapPost("/canary/rules", async (ICanaryRuleStore canaryRuleStore, List<CanaryRule> rules, CancellationToken ct) =>
        {
            var normalized = (rules ?? [])
                .Select(rule => rule with
                {
                    RuleId = string.IsNullOrWhiteSpace(rule.RuleId) ? Guid.NewGuid().ToString("N") : rule.RuleId.Trim(),
                    ActionType = string.IsNullOrWhiteSpace(rule.ActionType) ? "global" : rule.ActionType.Trim(),
                    CanaryPercent = Math.Clamp(rule.CanaryPercent, 0, 100)
                })
                .ToList();
            await canaryRuleStore.SaveAsync(normalized, ct);
            return Results.Ok(new { success = true, count = normalized.Count });
        });
    }

    public sealed record RestoreVersionRequest(string VersionId);

    public sealed record RestoreCatalogVersionRequest(string CatalogTarget, string VersionId);
}
