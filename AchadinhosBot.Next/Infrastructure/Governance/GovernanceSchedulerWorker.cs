using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Governance;
using AchadinhosBot.Next.Domain.Offers;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Governance;

public sealed class GovernanceSchedulerWorker : BackgroundService
{
    private readonly IGovernanceEventStore _eventStore;
    private readonly IGovernanceRuleEngine _ruleEngine;
    private readonly IGovernanceActionExecutor _actionExecutor;
    private readonly IAutoTuningService _autoTuningService;
    private readonly IOfferAnomalyDetector _offerAnomalyDetector;
    private readonly GovernanceOptions _options;
    private readonly ILogger<GovernanceSchedulerWorker> _logger;

    public GovernanceSchedulerWorker(
        IGovernanceEventStore eventStore,
        IGovernanceRuleEngine ruleEngine,
        IGovernanceActionExecutor actionExecutor,
        IAutoTuningService autoTuningService,
        IOfferAnomalyDetector offerAnomalyDetector,
        IOptions<GovernanceOptions> options,
        ILogger<GovernanceSchedulerWorker> logger)
    {
        _eventStore = eventStore;
        _ruleEngine = ruleEngine;
        _actionExecutor = actionExecutor;
        _autoTuningService = autoTuningService;
        _offerAnomalyDetector = offerAnomalyDetector;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled || !_options.SchedulerEnabled)
        {
            _logger.LogInformation("GovernanceSchedulerWorker desativado por configuração.");
            return;
        }

        var interval = TimeSpan.FromSeconds(Math.Clamp(_options.SchedulerIntervalSeconds, 10, 300));
        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await RunTickAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha no tick do scheduler de governança.");
            }
        }
    }

    private async Task RunTickAsync(CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        await _eventStore.AppendEventAsync(new GovernanceEvent(
            GovernanceTracks.Observe,
            "governance.tick.start",
            "info",
            "ok",
            "scheduler-orchestrator",
            "scheduler",
            "governance",
            null,
            null,
            null,
            started,
            "{}"), cancellationToken);

        var decisions = await _ruleEngine.EvaluateAsync(cancellationToken);
        foreach (var decision in decisions)
        {
            await _eventStore.AppendDecisionAsync(decision, cancellationToken);
            await _eventStore.AppendEventAsync(new GovernanceEvent(
                GovernanceTracks.Decide,
                $"decision.{decision.DecisionType}",
                decision.Severity,
                "triggered",
                decision.SkillName,
                decision.EntityType,
                decision.EntityId,
                null,
                null,
                null,
                DateTimeOffset.UtcNow,
                decision.MetadataJson), cancellationToken);

            var incident = new IncidentState(
                decision.DecisionId,
                decision.DecisionType,
                decision.Severity,
                "open",
                decision.Summary,
                decision.MetadataJson,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                null);
            await _eventStore.UpsertIncidentAsync(incident, cancellationToken);

            if (_options.ShadowMode)
            {
                await _eventStore.AppendActionAsync(new ActionExecution(
                    Guid.NewGuid().ToString("N"),
                    decision.DecisionType,
                    decision.Severity,
                    true,
                    false,
                    "Shadow mode ativo: ação simulada.",
                    decision.MetadataJson,
                    DateTimeOffset.UtcNow), cancellationToken);
                continue;
            }

            var action = await _actionExecutor.ExecuteAsync(decision, cancellationToken);
            await _eventStore.AppendActionAsync(action, cancellationToken);

            if (action.Success)
            {
                await _eventStore.ResolveIncidentAsync(decision.DecisionId, $"Resolvido por ação {action.ActionType}.", cancellationToken);
            }
        }

        if (_options.AutoTuningEnabled)
        {
            var tuningChanges = await _autoTuningService.RunAsync(cancellationToken);
            foreach (var change in tuningChanges)
            {
                await _eventStore.AppendTuningChangeAsync(change, cancellationToken);
                await _eventStore.AppendEventAsync(new GovernanceEvent(
                    GovernanceTracks.Act,
                    "tuning.change.applied",
                    "info",
                    "ok",
                    "auto-tuning-orchestrator",
                    "setting",
                    change.ParameterName,
                    null,
                    null,
                    null,
                    change.TimestampUtc,
                    JsonSerializer.Serialize(change)), cancellationToken);
            }
        }

        await ProcessOfferAnomaliesAsync(cancellationToken);

        await _eventStore.AppendEventAsync(new GovernanceEvent(
            GovernanceTracks.Audit,
            "governance.tick.finish",
            "info",
            "ok",
            "scheduler-orchestrator",
            "scheduler",
            "governance",
            null,
            null,
            (long)(DateTimeOffset.UtcNow - started).TotalMilliseconds,
            DateTimeOffset.UtcNow,
            JsonSerializer.Serialize(new { decisions = decisions.Count })), cancellationToken);
    }

    private async Task ProcessOfferAnomaliesAsync(CancellationToken cancellationToken)
    {
        var anomalies = await _offerAnomalyDetector.DetectAsync(cancellationToken);
        foreach (var anomaly in anomalies)
        {
            var incidentId = $"offer-anomaly:{anomaly.OfferId}";
            var incident = new IncidentState(
                incidentId,
                "offer_anomaly",
                anomaly.Severity,
                "open",
                anomaly.Summary,
                JsonSerializer.Serialize(anomaly),
                anomaly.DetectedAtUtc,
                anomaly.DetectedAtUtc,
                null);
            await _eventStore.UpsertIncidentAsync(incident, cancellationToken);
            await _eventStore.AppendEventAsync(new GovernanceEvent(
                GovernanceTracks.Observe,
                "offer.anomaly.detected",
                anomaly.Severity,
                "flagged",
                "offer-anomaly-detector",
                "offer",
                anomaly.OfferId,
                null,
                null,
                null,
                anomaly.DetectedAtUtc,
                JsonSerializer.Serialize(anomaly)), cancellationToken);
        }
    }
}
