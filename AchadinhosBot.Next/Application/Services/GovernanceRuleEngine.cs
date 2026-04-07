using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Governance;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed class GovernanceRuleEngine : IGovernanceRuleEngine
{
    private readonly IGovernanceEventStore _eventStore;
    private readonly IBotConversorOutboxStore _botOutbox;
    private readonly IWhatsAppOutboundOutboxStore _whatsAppOutbox;
    private readonly ITelegramOutboundOutboxStore _telegramOutbox;
    private readonly IInstagramOutboundOutboxStore _instagramOutbox;
    private readonly ICanaryRuleStore _canaryRuleStore;
    private readonly WorkerActivityTracker _workerActivityTracker;
    private readonly GovernanceOptions _options;

    public GovernanceRuleEngine(
        IGovernanceEventStore eventStore,
        IBotConversorOutboxStore botOutbox,
        IWhatsAppOutboundOutboxStore whatsAppOutbox,
        ITelegramOutboundOutboxStore telegramOutbox,
        IInstagramOutboundOutboxStore instagramOutbox,
        ICanaryRuleStore canaryRuleStore,
        WorkerActivityTracker workerActivityTracker,
        IOptions<GovernanceOptions> options)
    {
        _eventStore = eventStore;
        _botOutbox = botOutbox;
        _whatsAppOutbox = whatsAppOutbox;
        _telegramOutbox = telegramOutbox;
        _instagramOutbox = instagramOutbox;
        _canaryRuleStore = canaryRuleStore;
        _workerActivityTracker = workerActivityTracker;
        _options = options.Value;
    }

    public async Task<IReadOnlyList<GovernanceDecision>> EvaluateAsync(CancellationToken cancellationToken)
    {
        var decisions = new List<GovernanceDecision>();
        var now = DateTimeOffset.UtcNow;

        var botPending = (await _botOutbox.ListPendingAsync(cancellationToken)).Count;
        var waPending = (await _whatsAppOutbox.ListPendingAsync(cancellationToken)).Count;
        var tgPending = (await _telegramOutbox.ListPendingAsync(cancellationToken)).Count;
        var igPending = (await _instagramOutbox.ListPendingAsync(cancellationToken)).Count;
        var totalPending = botPending + waPending + tgPending + igPending;

        if (totalPending > _options.CriticalOutboxBacklogThreshold)
        {
            decisions.Add(new GovernanceDecision(
                Guid.NewGuid().ToString("N"),
                "force_outbox_replay",
                "critical",
                $"Outbox crítico detectado: total={totalPending}, threshold={_options.CriticalOutboxBacklogThreshold}.",
                "auto-healing-orchestrator",
                "outbox",
                "all",
                JsonSerializer.Serialize(new
                {
                    totalPending,
                    threshold = _options.CriticalOutboxBacklogThreshold,
                    byQueue = new { botPending, waPending, tgPending, igPending }
                }),
                now));
        }

        var workerStaleAfter = TimeSpan.FromSeconds(Math.Clamp(_options.WorkerStaleAfterSeconds, 30, 3600));
        foreach (var worker in _workerActivityTracker.ListSnapshots())
        {
            if (worker.LastSuccessUtc is null)
            {
                continue;
            }

            var stale = now - worker.LastSuccessUtc.Value;
            if (stale > workerStaleAfter)
            {
                decisions.Add(new GovernanceDecision(
                    Guid.NewGuid().ToString("N"),
                    "worker_recovery_attempt",
                    "warning",
                    $"Worker sem sucesso recente: {worker.WorkerName} há {Math.Round(stale.TotalSeconds)}s.",
                    "auto-healing-orchestrator",
                    "worker",
                    worker.WorkerName,
                    JsonSerializer.Serialize(new { worker.WorkerName, staleSeconds = stale.TotalSeconds, worker.LastError }),
                    now));
            }
        }

        if (_options.AutoRollbackEnabled)
        {
            var status = await _eventStore.GetStatusSnapshotAsync(cancellationToken);
            var canaryRules = await _canaryRuleStore.ListAsync(cancellationToken);
            var hasCanaryEnabled = canaryRules.Any(x => x.Enabled && x.CanaryPercent > 0);

            if (hasCanaryEnabled && (status.CriticalIncidents >= 2 || status.FailedActions24h >= 3))
            {
                decisions.Add(new GovernanceDecision(
                    Guid.NewGuid().ToString("N"),
                    "canary_rollback",
                    "critical",
                    "Threshold de falhas excedido com canario ativo; rollback instantaneo do canario acionado.",
                    "auto-rollback-orchestrator",
                    "canary",
                    "global",
                    JsonSerializer.Serialize(new
                    {
                        status.CriticalIncidents,
                        status.FailedActions24h,
                        activeRules = canaryRules.Count(x => x.Enabled && x.CanaryPercent > 0)
                    }),
                    now));
            }

            if (status.CriticalIncidents >= 3 || status.FailedActions24h >= 5)
            {
                decisions.Add(new GovernanceDecision(
                    Guid.NewGuid().ToString("N"),
                    "auto_rollback",
                    "critical",
                    "Degradação crítica recorrente detectada; avaliar rollback automático.",
                    "auto-rollback-orchestrator",
                    "runtime",
                    "global",
                    JsonSerializer.Serialize(new
                    {
                        status.CriticalIncidents,
                        status.FailedActions24h
                    }),
                    now));
            }
        }

        return decisions;
    }
}
