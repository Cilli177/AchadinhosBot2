using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WorkspaceAgentGatewayService
{
    private const string DefaultPin = "641989";

    private readonly ConcurrentDictionary<string, WorkspaceChatSession> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ISettingsStore _settingsStore;
    private readonly IAuditTrail _audit;
    private readonly OpenAiInstagramPostGenerator _openAiGenerator;
    private readonly NemotronInstagramPostGenerator _nemotronGenerator;
    private readonly QwenInstagramPostGenerator _qwenGenerator;
    private readonly GeminiInstagramPostGenerator _geminiGenerator;

    public WorkspaceAgentGatewayService(
        ISettingsStore settingsStore,
        IAuditTrail audit,
        OpenAiInstagramPostGenerator openAiGenerator,
        NemotronInstagramPostGenerator nemotronGenerator,
        QwenInstagramPostGenerator qwenGenerator,
        GeminiInstagramPostGenerator geminiGenerator)
    {
        _settingsStore = settingsStore;
        _audit = audit;
        _openAiGenerator = openAiGenerator;
        _nemotronGenerator = nemotronGenerator;
        _qwenGenerator = qwenGenerator;
        _geminiGenerator = geminiGenerator;
    }

    public async Task<(bool Success, string? Error, WorkspaceChatSession? Session)> OpenSessionAsync(
        string actor,
        string role,
        string pin,
        string provider,
        string environment,
        CancellationToken ct)
    {
        var settings = (await _settingsStore.GetAsync(ct)).AdminAiWorkspace ?? new AdminAiWorkspaceSettings();
        if (!settings.Enabled)
        {
            return (false, "AI workspace admin desabilitado.", null);
        }

        if (!settings.AllowedRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
        {
            return (false, "Perfil sem permissao para AI Ops.", null);
        }

        if (!IsPinValid(pin, settings.PinHash))
        {
            await _audit.WriteAsync("workspace.session.pin_invalid", actor, new { provider }, ct);
            return (false, "PIN invalido.", null);
        }

        var normalizedProvider = NormalizeProvider(provider);
        if (!settings.EnabledProviders.Contains(normalizedProvider, StringComparer.OrdinalIgnoreCase))
        {
            return (false, "Provider nao habilitado nas configuracoes.", null);
        }

        var now = DateTimeOffset.UtcNow;
        var session = new WorkspaceChatSession
        {
            SessionId = Guid.NewGuid().ToString("N"),
            UserId = actor,
            Provider = normalizedProvider,
            StartedAtUtc = now,
            ExpiresAtUtc = now.AddMinutes(settings.SessionDurationMinutes),
            WorkspacePath = ResolveWorkspaceRoot(),
            UnlockedWithPin = true,
            HasTerminalAccess = settings.AllowTerminal,
            HasWriteAccess = settings.AllowWorkspaceWrite,
            HasAdminAccess = settings.AllowAdminTerminal,
            CanReadWorkspace = true,
            CanWriteWorkspace = settings.AllowWorkspaceWrite,
            CanRunTerminal = settings.AllowTerminal,
            CanUseAdminMode = settings.AllowAdminTerminal,
            CanTouchProd = settings.AllowProdOperations,
            Environment = string.IsNullOrWhiteSpace(environment) ? "dev" : environment.Trim().ToLowerInvariant(),
            Status = "active"
        };

        _sessions[session.SessionId] = session;
        await _audit.WriteAsync("workspace.session.open", actor, new
        {
            session.SessionId,
            session.Provider,
            session.ExpiresAtUtc,
            session.Environment,
            session.CanTouchProd
        }, ct);

        return (true, null, session);
    }

    public async Task<bool> CloseSessionAsync(string actor, string sessionId, CancellationToken ct)
    {
        if (_sessions.TryGetValue(sessionId, out var session))
        {
            session.Status = "closed";
            _sessions.TryRemove(sessionId, out _);
            await _audit.WriteAsync("workspace.session.close", actor, new { sessionId }, ct);
            return true;
        }

        return false;
    }

    public WorkspaceChatSession? GetSession(string sessionId)
    {
        if (!_sessions.TryGetValue(sessionId, out var session))
        {
            return null;
        }

        if (session.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            session.Status = "expired";
            _sessions.TryRemove(session.SessionId, out _);
            return null;
        }

        return session;
    }

    public async Task<(bool Success, string? Error, string? Text, string? Connector)> SendChatAsync(
        WorkspaceChatSession session,
        string actor,
        string prompt,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(prompt))
        {
            return (false, "Prompt vazio.", null, null);
        }

        var settings = await _settingsStore.GetAsync(ct);
        var message = prompt.Trim();
        var connector = session.Provider;

        string text;
        string usedProvider = connector;
        try
        {
            var primary = await GenerateByProviderAsync(connector, message, settings, ct);
            if (!string.IsNullOrWhiteSpace(primary))
            {
                text = primary.Trim();
            }
            else
            {
                // Fallback operacional para evitar caixa de resposta vazia na UI.
                var fallbackOrder = new[] { "codex", "vscode", "antigravity", "gemini" }
                    .Where(x => !x.Equals(connector, StringComparison.OrdinalIgnoreCase));

                string? fallbackText = null;
                foreach (var fallback in fallbackOrder)
                {
                    fallbackText = await GenerateByProviderAsync(fallback, message, settings, ct);
                    if (!string.IsNullOrWhiteSpace(fallbackText))
                    {
                        usedProvider = fallback;
                        break;
                    }
                }

                text = !string.IsNullOrWhiteSpace(fallbackText)
                    ? $"[fallback:{usedProvider}]\n\n{fallbackText.Trim()}"
                    : "Sem resposta do motor selecionado. Verifique credenciais/configuracao do provider no IA Lab e tente novamente.";
            }
        }
        catch (Exception ex)
        {
            await _audit.WriteAsync("workspace.chat.failed", actor, new
            {
                session.SessionId,
                session.Provider,
                error = ex.Message
            }, ct);

            text = $"Falha ao consultar o motor ({connector}): {ex.Message}";
        }

        await _audit.WriteAsync("workspace.chat.prompt", actor, new
        {
            session.SessionId,
            session.Provider,
            usedProvider,
            promptLength = prompt.Length,
            responseLength = text.Length
        }, ct);

        return (true, null, text, connector);
    }

    private async Task<string?> GenerateByProviderAsync(string provider, string message, AutomationSettings settings, CancellationToken ct)
    {
        var normalized = NormalizeProvider(provider);
        return normalized switch
        {
            "codex" => await _openAiGenerator.GenerateFreeformAsync(message, settings.OpenAI ?? new OpenAISettings(), ct),
            "vscode" => await _nemotronGenerator.GenerateFreeformAsync(message, settings.Nemotron ?? new NemotronSettings(), ct),
            "antigravity" => await _qwenGenerator.GenerateFreeformAsync(message, settings.Qwen ?? new QwenSettings(), ct),
            "gemma4" => await _geminiGenerator.GenerateFreeformAsync(message, (settings.Gemma4 ?? new Gemma4Settings()).AsAdvanced(), ct),
            _ => await _geminiGenerator.GenerateFreeformAsync(message, settings.Gemini ?? new GeminiSettings(), ct)
        };
    }

    public async Task<(bool Success, string? Error, WorkspaceTerminalResult? Result)> ExecuteTerminalAsync(
        WorkspaceChatSession session,
        string actor,
        string command,
        int timeoutSeconds,
        bool confirmCritical,
        CancellationToken ct)
    {
        if (!session.CanRunTerminal)
        {
            return (false, "Terminal nao habilitado para a sessao.", null);
        }

        if (string.IsNullOrWhiteSpace(command))
        {
            return (false, "Comando vazio.", null);
        }

        if (!session.CanTouchProd && LooksLikeProdOperation(command))
        {
            return (false, "Comando bloqueado: operacao de PROD nao permitida para esta sessao.", null);
        }

        if (IsCriticalOperation(command) && !confirmCritical)
        {
            return (false, "Operacao critica exige confirmacao explicita.", null);
        }

        timeoutSeconds = Math.Clamp(timeoutSeconds, 5, 600);
        var root = ResolveWorkspaceRoot();
        var isWindows = OperatingSystem.IsWindows();
        var fileName = isWindows ? "powershell" : "/bin/bash";
        var arguments = isWindows
            ? $"-NoProfile -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\""
            : $"-lc \"{command.Replace("\"", "\\\"")}\"";

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        var startedAt = DateTimeOffset.UtcNow;
        process.Start();

        var outputTask = process.StandardOutput.ReadToEndAsync(ct);
        var errorTask = process.StandardError.ReadToEndAsync(ct);
        var waitTask = process.WaitForExitAsync(ct);
        var completedTask = await Task.WhenAny(waitTask, Task.Delay(TimeSpan.FromSeconds(timeoutSeconds), ct));

        var timedOut = completedTask != waitTask;
        if (timedOut)
        {
            try { process.Kill(true); } catch { }
        }
        else
        {
            await waitTask;
        }

        var stdout = await outputTask;
        var stderr = await errorTask;
        var merged = MergeOutput(stdout, stderr);

        var result = new WorkspaceTerminalResult
        {
            ExitCode = timedOut ? -1 : process.ExitCode,
            TimedOut = timedOut,
            Output = LimitOutput(merged, 64000),
            DurationMs = (long)(DateTimeOffset.UtcNow - startedAt).TotalMilliseconds,
            StartedAtUtc = startedAt
        };

        await _audit.WriteAsync("workspace.terminal.exec", actor, new
        {
            session.SessionId,
            command,
            result.ExitCode,
            result.TimedOut,
            result.DurationMs
        }, ct);

        return (true, null, result);
    }

    public async Task<(bool Success, string? Error, WorkspaceFileReadResult? Result)> ReadFileAsync(
        WorkspaceChatSession session,
        string actor,
        string relativePath,
        CancellationToken ct)
    {
        if (!session.CanReadWorkspace)
        {
            return (false, "Leitura de workspace nao habilitada para a sessao.", null);
        }

        var fullPath = ResolveWorkspacePath(relativePath);
        if (fullPath is null)
        {
            return (false, "Caminho invalido.", null);
        }

        if (!File.Exists(fullPath))
        {
            return (false, "Arquivo nao encontrado.", null);
        }

        var info = new FileInfo(fullPath);
        if (info.Length > 1024 * 1024)
        {
            return (false, "Arquivo maior que 1MB nao pode ser carregado nesta interface.", null);
        }

        var content = await File.ReadAllTextAsync(fullPath, ct);
        var result = new WorkspaceFileReadResult
        {
            Path = ToWorkspaceRelative(fullPath),
            Content = content,
            SizeBytes = info.Length,
            LastWriteAtUtc = info.LastWriteTimeUtc
        };

        await _audit.WriteAsync("workspace.file.read", actor, new
        {
            session.SessionId,
            path = result.Path,
            result.SizeBytes
        }, ct);

        return (true, null, result);
    }

    public async Task<(bool Success, string? Error)> WriteFileAsync(
        WorkspaceChatSession session,
        string actor,
        string relativePath,
        string content,
        bool confirmCritical,
        CancellationToken ct)
    {
        if (!session.CanWriteWorkspace)
        {
            return (false, "Escrita de workspace nao habilitada para a sessao.");
        }

        var fullPath = ResolveWorkspacePath(relativePath);
        if (fullPath is null)
        {
            return (false, "Caminho invalido.");
        }

        if (!session.CanTouchProd && LooksLikeProdFile(relativePath))
        {
            return (false, "Arquivo de PROD bloqueado para esta sessao.");
        }

        if (LooksLikeProdFile(relativePath) && !confirmCritical)
        {
            return (false, "Arquivo sensivel exige confirmacao critica.");
        }

        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(fullPath, content ?? string.Empty, ct);

        await _audit.WriteAsync("workspace.file.write", actor, new
        {
            session.SessionId,
            path = ToWorkspaceRelative(fullPath),
            length = content?.Length ?? 0
        }, ct);

        return (true, null);
    }

    private static string NormalizeProvider(string provider)
    {
        var normalized = (provider ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "codex" => "codex",
            "vscode" => "vscode",
            "antigravity" => "antigravity",
            _ => "codex"
        };
    }

    private static string ResolveWorkspaceRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var hasSolution = current.GetFiles("*.sln", SearchOption.TopDirectoryOnly).Length > 0;
            if (hasSolution)
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        return Directory.GetCurrentDirectory();
    }

    private static string? ResolveWorkspacePath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return null;
        }

        var normalized = relativePath.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar).Trim();
        var root = ResolveWorkspaceRoot();
        var full = Path.GetFullPath(Path.Combine(root, normalized));

        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return full;
    }

    private static string ToWorkspaceRelative(string fullPath)
    {
        var root = ResolveWorkspaceRoot();
        return Path.GetRelativePath(root, fullPath).Replace('\\', '/');
    }

    private static bool IsPinValid(string providedPin, string configuredHash)
    {
        var hash = string.IsNullOrWhiteSpace(configuredHash)
            ? ComputeSha256(DefaultPin)
            : configuredHash.Trim().ToLowerInvariant();

        return ComputeSha256(providedPin ?? string.Empty) == hash;
    }

    private static string ComputeSha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static bool LooksLikeProdOperation(string command)
    {
        var normalized = (command ?? string.Empty).ToLowerInvariant();
        return normalized.Contains("prod")
            || normalized.Contains("5005")
            || normalized.Contains("deploy-prod")
            || normalized.Contains("docker-compose.prod")
            || normalized.Contains("start-docker-prod");
    }

    private static bool IsCriticalOperation(string command)
    {
        var normalized = (command ?? string.Empty).ToLowerInvariant();
        return normalized.Contains("deploy")
            || normalized.Contains("docker compose")
            || normalized.Contains("restart")
            || normalized.Contains("stop-")
            || normalized.Contains("rm ");
    }

    private static bool LooksLikeProdFile(string path)
    {
        var normalized = (path ?? string.Empty).Replace('\\', '/').ToLowerInvariant();
        return normalized.Contains("prod") || normalized.EndsWith(".env.prod", StringComparison.OrdinalIgnoreCase);
    }

    private static string MergeOutput(string stdout, string stderr)
    {
        if (string.IsNullOrWhiteSpace(stderr))
        {
            return stdout ?? string.Empty;
        }

        if (string.IsNullOrWhiteSpace(stdout))
        {
            return stderr;
        }

        return stdout + Environment.NewLine + "[stderr]" + Environment.NewLine + stderr;
    }

    private static string LimitOutput(string value, int maxChars)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxChars)
        {
            return value ?? string.Empty;
        }

        return value[..maxChars] + Environment.NewLine + "[truncated]";
    }
}

public sealed class WorkspaceChatSession
{
    public string SessionId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Provider { get; set; } = "codex";
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public string WorkspacePath { get; set; } = string.Empty;
    public bool UnlockedWithPin { get; set; }
    public bool HasTerminalAccess { get; set; }
    public bool HasWriteAccess { get; set; }
    public bool HasAdminAccess { get; set; }
    public bool CanReadWorkspace { get; set; }
    public bool CanWriteWorkspace { get; set; }
    public bool CanRunTerminal { get; set; }
    public bool CanUseAdminMode { get; set; }
    public bool CanTouchProd { get; set; }
    public string Environment { get; set; } = "dev";
    public string Status { get; set; } = "active";
}

public sealed class WorkspaceTerminalResult
{
    public int ExitCode { get; set; }
    public bool TimedOut { get; set; }
    public string Output { get; set; } = string.Empty;
    public long DurationMs { get; set; }
    public DateTimeOffset StartedAtUtc { get; set; }
}

public sealed class WorkspaceFileReadResult
{
    public string Path { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public DateTime LastWriteAtUtc { get; set; }
}
