using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using AchadinhosBot.Next.Infrastructure.Resilience;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using System.Net.Http.Headers;
using System.Text.Json;

namespace AchadinhosBot.Next;

public sealed class OperationalReadinessService
{
    private readonly WorkerActivityTracker _workerActivityTracker;
    private readonly IWhatsAppTransport _whatsAppTransport;
    private readonly ITelegramUserbotService _telegramUserbotService;
    private readonly IBotConversorOutboxStore _botConversorOutboxStore;
    private readonly IWhatsAppOutboundOutboxStore _whatsAppOutboundOutboxStore;
    private readonly ITelegramOutboundOutboxStore _telegramOutboundOutboxStore;
    private readonly IInstagramOutboundOutboxStore _instagramOutboundOutboxStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly OperationalReadinessOptions _readinessOptions;
    private readonly EvolutionOptions _evolutionOptions;
    private readonly IConfiguration _configuration;

    public OperationalReadinessService(
        WorkerActivityTracker workerActivityTracker,
        IWhatsAppTransport whatsAppTransport,
        ITelegramUserbotService telegramUserbotService,
        IBotConversorOutboxStore botConversorOutboxStore,
        IWhatsAppOutboundOutboxStore whatsAppOutboundOutboxStore,
        ITelegramOutboundOutboxStore telegramOutboundOutboxStore,
        IInstagramOutboundOutboxStore instagramOutboundOutboxStore,
        IOptions<MessagingOptions> messagingOptions,
        IOptions<OperationalReadinessOptions> readinessOptions,
        IOptions<EvolutionOptions> evolutionOptions,
        IConfiguration configuration)
    {
        _workerActivityTracker = workerActivityTracker;
        _whatsAppTransport = whatsAppTransport;
        _telegramUserbotService = telegramUserbotService;
        _botConversorOutboxStore = botConversorOutboxStore;
        _whatsAppOutboundOutboxStore = whatsAppOutboundOutboxStore;
        _telegramOutboundOutboxStore = telegramOutboundOutboxStore;
        _instagramOutboundOutboxStore = instagramOutboundOutboxStore;
        _messagingOptions = messagingOptions.Value;
        _readinessOptions = readinessOptions.Value;
        _evolutionOptions = evolutionOptions.Value;
        _configuration = configuration;
    }

    public async Task<OperationalReadinessReport> EvaluateAsync(
        bool startTelegramBotWorker,
        bool startTelegramUserbotWorker,
        CancellationToken cancellationToken)
    {
        var issues = new List<string>();
        var checks = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var runtimeRole = ResolveRuntimeRole();
        var workerChecksEnabled = IsWorkerRuntime(runtimeRole);

        var dependencyTimeout = TimeSpan.FromSeconds(Math.Clamp(_readinessOptions.DependencyTimeoutSeconds, 2, 30));
        checks["runtimeRole"] = runtimeRole;
        checks["workerChecksEnabled"] = workerChecksEnabled;

        var rabbitMqReachable = await CanReachRabbitMqAsync(dependencyTimeout, cancellationToken);
        checks["rabbitMqReachable"] = rabbitMqReachable;
        if (!rabbitMqReachable)
        {
            issues.Add("RabbitMQ indisponivel para conexao de readiness.");
        }

        var evolutionReady = await CanReachEvolutionAsync(dependencyTimeout, cancellationToken);
        var requireEvolutionReady = _readinessOptions.RequireEvolutionReady;
        checks["evolutionReady"] = evolutionReady;
        checks["evolutionRequired"] = requireEvolutionReady;
        if (requireEvolutionReady && !evolutionReady)
        {
            issues.Add("Evolution/WhatsApp indisponivel ou nao autenticado.");
        }

        var telegramUserbotReady = !startTelegramUserbotWorker || _telegramUserbotService.IsReady;
        checks["telegramUserbotReady"] = telegramUserbotReady;
        checks["telegramBotWorkerEnabled"] = startTelegramBotWorker;
        checks["telegramUserbotWorkerEnabled"] = startTelegramUserbotWorker;
        if (!telegramUserbotReady)
        {
            issues.Add("Telegram userbot habilitado, mas ainda nao esta pronto.");
        }

        var workerStates = workerChecksEnabled ? BuildWorkerStates() : Array.Empty<OperationalWorkerState>();
        checks["workers"] = workerStates;
        foreach (var workerState in workerStates.Where(x => !x.Healthy))
        {
            issues.Add(workerState.Message);
        }

        var criticalOutboxBacklog = Math.Max(1, _readinessOptions.CriticalOutboxBacklog);
        var outboxBacklogs = await BuildOutboxBacklogsAsync(cancellationToken);
        checks["outboxes"] = outboxBacklogs;
        foreach (var backlog in outboxBacklogs)
        {
            if (backlog.PendingCount > criticalOutboxBacklog)
            {
                issues.Add($"Outbox {backlog.Name} acima do limite critico ({backlog.PendingCount}>{criticalOutboxBacklog}).");
            }
        }

        return new OperationalReadinessReport(issues.Count == 0, issues, checks);
    }

    private string ResolveRuntimeRole()
    {
        var configuredRole = _configuration["APP__ROLE"]
            ?? _configuration["App:Role"]
            ?? "all";

        return configuredRole.Trim().ToLowerInvariant();
    }

    private static bool IsWorkerRuntime(string runtimeRole)
        => string.Equals(runtimeRole, "worker", StringComparison.OrdinalIgnoreCase)
        || string.Equals(runtimeRole, "all", StringComparison.OrdinalIgnoreCase);

    private IReadOnlyList<OperationalWorkerState> BuildWorkerStates()
    {
        var staleAfter = TimeSpan.FromSeconds(Math.Clamp(_readinessOptions.WorkerStaleAfterSeconds, 30, 3600));
        var outboxReplayStaleAfter = TimeSpan.FromSeconds(Math.Max(
            _messagingOptions.OutboxReplayIntervalSeconds * 2,
            (int)staleAfter.TotalSeconds));

        return
        [
            BuildWorkerState(nameof(BotConversorOutboxReplayWorker), outboxReplayStaleAfter),
            BuildWorkerState(nameof(WhatsAppOutboundReplayWorker), outboxReplayStaleAfter),
            BuildWorkerState(nameof(TelegramOutboundReplayWorker), outboxReplayStaleAfter),
            BuildWorkerState(nameof(InstagramOutboundReplayService), TimeSpan.FromMinutes(25))
        ];
    }

    private OperationalWorkerState BuildWorkerState(string workerName, TimeSpan staleAfter)
    {
        var snapshot = _workerActivityTracker.GetSnapshot(workerName);
        if (snapshot is null)
        {
            return new OperationalWorkerState(workerName, false, $"Worker {workerName} ainda nao reportou atividade.");
        }

        if (snapshot.LastSuccessUtc is null)
        {
            return new OperationalWorkerState(workerName, false, $"Worker {workerName} ainda nao concluiu um ciclo com sucesso.");
        }

        var age = DateTimeOffset.UtcNow - snapshot.LastSuccessUtc.Value;
        if (age > staleAfter)
        {
            return new OperationalWorkerState(workerName, false, $"Worker {workerName} sem sucesso recente ha {Math.Round(age.TotalSeconds)}s.");
        }

        return new OperationalWorkerState(workerName, true, "ok", snapshot.LastSuccessUtc, snapshot.LastFailureUtc, snapshot.LastError);
    }

    private async Task<IReadOnlyList<OperationalOutboxBacklog>> BuildOutboxBacklogsAsync(CancellationToken cancellationToken)
    {
        var botConversor = await _botConversorOutboxStore.ListPendingAsync(cancellationToken);
        var whatsApp = await _whatsAppOutboundOutboxStore.ListPendingAsync(cancellationToken);
        var telegram = await _telegramOutboundOutboxStore.ListPendingAsync(cancellationToken);
        var instagram = await _instagramOutboundOutboxStore.ListPendingAsync(cancellationToken);

        return
        [
            new OperationalOutboxBacklog("bot-conversor", botConversor.Count),
            new OperationalOutboxBacklog("whatsapp", whatsApp.Count),
            new OperationalOutboxBacklog("telegram", telegram.Count),
            new OperationalOutboxBacklog("instagram", instagram.Count)
        ];
    }

    private async Task<bool> CanReachEvolutionAsync(TimeSpan dependencyTimeout, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_evolutionOptions.BaseUrl) ||
            string.IsNullOrWhiteSpace(_evolutionOptions.ApiKey))
        {
            return false;
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(dependencyTimeout);

        try
        {
            using var client = new HttpClient
            {
                BaseAddress = new Uri(_evolutionOptions.BaseUrl, UriKind.Absolute),
                Timeout = dependencyTimeout
            };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _evolutionOptions.ApiKey);
            client.DefaultRequestHeaders.Add("apikey", _evolutionOptions.ApiKey);
            client.DefaultRequestHeaders.Add("x-api-key", _evolutionOptions.ApiKey);

            var targetInstance = string.IsNullOrWhiteSpace(_evolutionOptions.InstanceName)
                ? "default"
                : _evolutionOptions.InstanceName.Trim();

            var response = await client.GetAsync($"/instance/connectionState/{targetInstance}", timeoutCts.Token);
            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            var body = await response.Content.ReadAsStringAsync(timeoutCts.Token);
            var state = ExtractEvolutionState(body);
            if (!string.IsNullOrWhiteSpace(state))
            {
                var normalizedState = state.Trim();
                var allowedStates = _readinessOptions.AllowedEvolutionStates
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim())
                    .ToArray();

                if (allowedStates.Any(x => string.Equals(x, normalizedState, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static string? ExtractEvolutionState(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;

            if (root.TryGetProperty("instance", out var instanceNode) &&
                instanceNode.ValueKind == JsonValueKind.Object &&
                instanceNode.TryGetProperty("state", out var instanceState))
            {
                return instanceState.GetString();
            }

            if (root.TryGetProperty("state", out var rootState))
            {
                return rootState.GetString();
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private Task<bool> CanReachRabbitMqAsync(TimeSpan dependencyTimeout, CancellationToken cancellationToken)
    {
        try
        {
            var host = _configuration["RabbitMq:Host"] ?? _configuration["RABBITMQ__HOST"] ?? "localhost";
            var virtualHost = _configuration["RabbitMq:VirtualHost"] ?? _configuration["RABBITMQ__VIRTUALHOST"] ?? "/";
            var user = _configuration["RabbitMq:Username"] ?? _configuration["RABBITMQ__USERNAME"] ?? "guest";
            var password = _configuration["RabbitMq:Password"] ?? _configuration["RABBITMQ__PASSWORD"] ?? "guest";

            var factory = new ConnectionFactory
            {
                HostName = host,
                VirtualHost = virtualHost,
                UserName = user,
                Password = password,
                AutomaticRecoveryEnabled = false,
                RequestedConnectionTimeout = dependencyTimeout
            };

            cancellationToken.ThrowIfCancellationRequested();
            using var connection = factory.CreateConnection("achadinhos-readiness");
            return Task.FromResult(connection.IsOpen);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }
}

public sealed record OperationalReadinessReport(
    bool Ready,
    IReadOnlyList<string> Issues,
    IReadOnlyDictionary<string, object?> Checks);

public sealed record OperationalWorkerState(
    string WorkerName,
    bool Healthy,
    string Message,
    DateTimeOffset? LastSuccessUtc = null,
    DateTimeOffset? LastFailureUtc = null,
    string? LastError = null);

public sealed record OperationalOutboxBacklog(string Name, int PendingCount);
