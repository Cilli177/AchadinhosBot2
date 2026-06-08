using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Endpoints;

public static class WorkspaceAgentEndpoints
{
    public static void MapWorkspaceAgentEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/admin/workspace-agent").RequireAuthorization("ReadAccess");

        group.MapGet("/settings", async (ISettingsStore store, HttpContext context, CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var settings = (await store.GetAsync(ct)).AdminAiWorkspace ?? new AdminAiWorkspaceSettings();
            return Results.Ok(new
            {
                settings.Enabled,
                settings.AllowedRoles,
                settings.SessionDurationMinutes,
                settings.AllowTerminal,
                settings.AllowAdminTerminal,
                settings.AllowWorkspaceWrite,
                settings.AllowProdOperations,
                settings.EnabledProviders,
                settings.AuditEnabled,
                settings.CriticalConfirmationText,
                pinConfigured = !string.IsNullOrWhiteSpace(settings.PinHash)
            });
        });

        group.MapPut("/settings", async (
            WorkspaceAgentSettingsUpdateRequest payload,
            ISettingsStore store,
            IAuditTrail audit,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var settings = await store.GetAsync(ct);
            var target = settings.AdminAiWorkspace ??= new AdminAiWorkspaceSettings();
            target.Enabled = payload.Enabled;
            target.AllowedRoles = NormalizeRoles(payload.AllowedRoles);
            target.SessionDurationMinutes = Math.Clamp(payload.SessionDurationMinutes, 5, 240);
            target.AllowTerminal = payload.AllowTerminal;
            target.AllowAdminTerminal = payload.AllowAdminTerminal;
            target.AllowWorkspaceWrite = payload.AllowWorkspaceWrite;
            target.AllowProdOperations = payload.AllowProdOperations;
            target.EnabledProviders = NormalizeProviders(payload.EnabledProviders);
            target.AuditEnabled = payload.AuditEnabled;
            target.CriticalConfirmationText = string.IsNullOrWhiteSpace(payload.CriticalConfirmationText)
                ? "CONFIRMAR-PROD"
                : payload.CriticalConfirmationText.Trim();

            if (!string.IsNullOrWhiteSpace(payload.Pin))
            {
                target.PinHash = ComputeSha256(payload.Pin.Trim());
            }

            await store.SaveAsync(settings, ct);
            await audit.WriteAsync("workspace.settings.update", context.User.Identity?.Name ?? "unknown", new
            {
                target.Enabled,
                target.SessionDurationMinutes,
                target.AllowTerminal,
                target.AllowAdminTerminal,
                target.AllowWorkspaceWrite,
                target.AllowProdOperations,
                target.EnabledProviders
            }, ct);

            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminOnly");

        group.MapPost("/session/open", async (
            WorkspaceSessionOpenRequest request,
            WorkspaceAgentGatewayService gateway,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var role = context.User.FindFirst(ClaimTypes.Role)?.Value ?? "";
            var open = await gateway.OpenSessionAsync(actor, role, request.Pin ?? string.Empty, request.Provider ?? "codex", request.Environment ?? "dev", ct);
            if (!open.Success || open.Session is null)
            {
                return Results.BadRequest(new { success = false, error = open.Error ?? "Falha ao abrir sessao." });
            }

            return Results.Ok(new { success = true, session = open.Session });
        }).RequireAuthorization("AdminOnly");

        group.MapPost("/session/close", async (
            WorkspaceSessionCloseRequest request,
            WorkspaceAgentGatewayService gateway,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var ok = await gateway.CloseSessionAsync(actor, request.SessionId ?? string.Empty, ct);
            return ok ? Results.Ok(new { success = true }) : Results.NotFound(new { success = false, error = "Sessao nao encontrada." });
        });

        group.MapGet("/session/{sessionId}", (string sessionId, WorkspaceAgentGatewayService gateway, HttpContext context) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var session = gateway.GetSession(sessionId);
            if (session is null)
            {
                return Results.NotFound(new { success = false, error = "Sessao nao encontrada ou expirada." });
            }

            return Results.Ok(new { success = true, session });
        });

        group.MapPost("/chat", async (
            WorkspaceChatRequest request,
            WorkspaceAgentGatewayService gateway,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var session = gateway.GetSession(request.SessionId ?? string.Empty);
            if (session is null)
            {
                return Results.BadRequest(new { success = false, error = "Sessao expirada ou invalida." });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var chat = await gateway.SendChatAsync(session, actor, request.Prompt ?? string.Empty, ct);
            if (!chat.Success)
            {
                return Results.BadRequest(new { success = false, error = chat.Error });
            }

            return Results.Ok(new
            {
                success = true,
                provider = chat.Connector,
                text = chat.Text
            });
        });

        group.MapPost("/terminal", async (
            WorkspaceTerminalRequest request,
            WorkspaceAgentGatewayService gateway,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var session = gateway.GetSession(request.SessionId ?? string.Empty);
            if (session is null)
            {
                return Results.BadRequest(new { success = false, error = "Sessao expirada ou invalida." });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var run = await gateway.ExecuteTerminalAsync(
                session,
                actor,
                request.Command ?? string.Empty,
                request.TimeoutSeconds,
                request.ConfirmCritical,
                ct);

            if (!run.Success || run.Result is null)
            {
                return Results.BadRequest(new { success = false, error = run.Error });
            }

            return Results.Ok(new { success = true, result = run.Result });
        });

        group.MapPost("/files/read", async (
            WorkspaceFileReadRequest request,
            WorkspaceAgentGatewayService gateway,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var session = gateway.GetSession(request.SessionId ?? string.Empty);
            if (session is null)
            {
                return Results.BadRequest(new { success = false, error = "Sessao expirada ou invalida." });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var read = await gateway.ReadFileAsync(session, actor, request.Path ?? string.Empty, ct);
            if (!read.Success || read.Result is null)
            {
                return Results.BadRequest(new { success = false, error = read.Error });
            }

            return Results.Ok(new { success = true, file = read.Result });
        });

        group.MapPost("/files/write", async (
            WorkspaceFileWriteRequest request,
            WorkspaceAgentGatewayService gateway,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (!IsAdminRole(context))
            {
                return Results.Unauthorized();
            }

            var session = gateway.GetSession(request.SessionId ?? string.Empty);
            if (session is null)
            {
                return Results.BadRequest(new { success = false, error = "Sessao expirada ou invalida." });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var saved = await gateway.WriteFileAsync(
                session,
                actor,
                request.Path ?? string.Empty,
                request.Content ?? string.Empty,
                request.ConfirmCritical,
                ct);

            if (!saved.Success)
            {
                return Results.BadRequest(new { success = false, error = saved.Error });
            }

            return Results.Ok(new { success = true });
        });
    }

    private static bool IsAdminRole(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        var role = context.User.FindFirst(ClaimTypes.Role)?.Value;
        return string.Equals(role, "admin", StringComparison.OrdinalIgnoreCase);
    }

    private static List<string> NormalizeRoles(List<string>? roles)
    {
        var result = (roles ?? new List<string> { "admin" })
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim().ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return result.Count == 0 ? new List<string> { "admin" } : result;
    }

    private static List<string> NormalizeProviders(List<string>? providers)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "codex",
            "vscode",
            "antigravity"
        };

        var result = (providers ?? new List<string> { "codex", "vscode", "antigravity" })
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim().ToLowerInvariant())
            .Where(x => allowed.Contains(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return result.Count == 0 ? new List<string> { "codex", "vscode", "antigravity" } : result;
    }

    private static string ComputeSha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

public sealed record WorkspaceSessionOpenRequest(string Provider, string Pin, string? Environment = null);
public sealed record WorkspaceSessionCloseRequest(string SessionId);
public sealed record WorkspaceChatRequest(string SessionId, string Prompt);
public sealed record WorkspaceTerminalRequest(string SessionId, string Command, int TimeoutSeconds = 120, bool ConfirmCritical = false);
public sealed record WorkspaceFileReadRequest(string SessionId, string Path);
public sealed record WorkspaceFileWriteRequest(string SessionId, string Path, string Content, bool ConfirmCritical = false);

public sealed class WorkspaceAgentSettingsUpdateRequest
{
    public bool Enabled { get; set; } = true;
    public List<string> AllowedRoles { get; set; } = new() { "admin" };
    public string? Pin { get; set; }
    public int SessionDurationMinutes { get; set; } = 45;
    public bool AllowTerminal { get; set; } = true;
    public bool AllowAdminTerminal { get; set; } = true;
    public bool AllowWorkspaceWrite { get; set; } = true;
    public bool AllowProdOperations { get; set; }
    public List<string> EnabledProviders { get; set; } = new() { "codex", "vscode", "antigravity" };
    public bool AuditEnabled { get; set; } = true;
    public string CriticalConfirmationText { get; set; } = "CONFIRMAR-PROD";
}
