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
            var recent = await store.ListEventsAsync(null, 300, ct);
            var bySkill = recent
                .Where(x => !string.IsNullOrWhiteSpace(x.SkillName))
                .GroupBy(x => x.SkillName!, StringComparer.OrdinalIgnoreCase)
                .Select(g => new
                {
                    skill = g.Key,
                    total = g.Count(),
                    failed = g.Count(x => string.Equals(x.Result, "failed", StringComparison.OrdinalIgnoreCase)),
                    critical = g.Count(x => string.Equals(x.Severity, "critical", StringComparison.OrdinalIgnoreCase)),
                    lastAt = g.Max(x => x.TimestampUtc)
                })
                .OrderByDescending(x => x.total)
                .ToArray();

            return Results.Ok(new
            {
                snapshot = status,
                skillHealth = bySkill
            });
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

        admin.MapGet("/governance/anomalies", async (
            IGovernanceEventStore store,
            [FromQuery] bool onlyOpen,
            [FromQuery] int limit,
            CancellationToken ct) =>
        {
            var incidents = await store.ListIncidentsAsync(onlyOpen, limit <= 0 ? 100 : limit, ct);
            var anomalies = incidents
                .Where(x => string.Equals(x.IncidentType, "offer_anomaly", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            return Results.Ok(anomalies);
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
