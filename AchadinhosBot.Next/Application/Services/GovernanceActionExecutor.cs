using System.Collections.Concurrent;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Governance;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed class GovernanceActionExecutor : IGovernanceActionExecutor
{
    private readonly IBotConversorOutboxStore _botOutbox;
    private readonly IWhatsAppOutboundOutboxStore _whatsAppOutbox;
    private readonly ITelegramOutboundOutboxStore _telegramOutbox;
    private readonly IInstagramOutboundOutboxStore _instagramOutbox;
    private readonly IBotConversorQueuePublisher _botPublisher;
    private readonly IWhatsAppOutboundPublisher _whatsAppPublisher;
    private readonly ITelegramOutboundPublisher _telegramPublisher;
    private readonly IInstagramOutboundPublisher _instagramPublisher;
    private readonly ISettingsStore _settingsStore;
    private readonly ICanaryRuleStore _canaryRuleStore;
    private readonly GovernanceOptions _options;
    private readonly ConcurrentQueue<DateTimeOffset> _actionWindow = new();

    public GovernanceActionExecutor(
        IBotConversorOutboxStore botOutbox,
        IWhatsAppOutboundOutboxStore whatsAppOutbox,
        ITelegramOutboundOutboxStore telegramOutbox,
        IInstagramOutboundOutboxStore instagramOutbox,
        IBotConversorQueuePublisher botPublisher,
        IWhatsAppOutboundPublisher whatsAppPublisher,
        ITelegramOutboundPublisher telegramPublisher,
        IInstagramOutboundPublisher instagramPublisher,
        ISettingsStore settingsStore,
        ICanaryRuleStore canaryRuleStore,
        IOptions<GovernanceOptions> options)
    {
        _botOutbox = botOutbox;
        _whatsAppOutbox = whatsAppOutbox;
        _telegramOutbox = telegramOutbox;
        _instagramOutbox = instagramOutbox;
        _botPublisher = botPublisher;
        _whatsAppPublisher = whatsAppPublisher;
        _telegramPublisher = telegramPublisher;
        _instagramPublisher = instagramPublisher;
        _settingsStore = settingsStore;
        _canaryRuleStore = canaryRuleStore;
        _options = options.Value;
    }

    public async Task<ActionExecution> ExecuteAsync(GovernanceDecision decision, CancellationToken cancellationToken)
    {
        if (IsCircuitOpen())
        {
            return new ActionExecution(
                Guid.NewGuid().ToString("N"),
                decision.DecisionType,
                decision.Severity,
                false,
                false,
                "Circuit breaker aberto: limite de ações automáticas atingido na janela.",
                JsonSerializer.Serialize(new { limit = _options.MaxActionsPerWindow, windowMinutes = _options.ActionWindowMinutes }),
                DateTimeOffset.UtcNow);
        }

        switch (decision.DecisionType)
        {
            case "force_outbox_replay":
                return await ExecuteForceOutboxReplayAsync(decision, cancellationToken);

            case "worker_recovery_attempt":
                return await ExecuteWorkerRecoveryAsync(decision, cancellationToken);

            case "auto_rollback":
                return await ExecuteAutoRollbackAsync(decision, cancellationToken);

            case "canary_rollback":
                return await ExecuteCanaryRollbackAsync(decision, cancellationToken);

            default:
                return new ActionExecution(
                    Guid.NewGuid().ToString("N"),
                    decision.DecisionType,
                    decision.Severity,
                    false,
                    false,
                    "Tipo de ação não suportado pelo executor.",
                    JsonSerializer.Serialize(new { decision.DecisionType }),
                    DateTimeOffset.UtcNow);
        }
    }

    private async Task<ActionExecution> ExecuteForceOutboxReplayAsync(GovernanceDecision decision, CancellationToken cancellationToken)
    {
        var replayed = new
        {
            bot = await ReplayBotAsync(cancellationToken),
            whatsapp = await ReplayWhatsAppAsync(cancellationToken),
            telegram = await ReplayTelegramAsync(cancellationToken),
            instagram = await ReplayInstagramAsync(cancellationToken)
        };
        RegisterAction();
        return new ActionExecution(
            Guid.NewGuid().ToString("N"),
            decision.DecisionType,
            decision.Severity,
            true,
            false,
            "Replay forçado de outbox executado.",
            JsonSerializer.Serialize(replayed),
            DateTimeOffset.UtcNow);
    }

    private async Task<ActionExecution> ExecuteWorkerRecoveryAsync(GovernanceDecision decision, CancellationToken cancellationToken)
    {
        // Recovery seguro: aciona replay rápido e registra ação.
        var replay = await ExecuteForceOutboxReplayAsync(decision, cancellationToken);
        return replay with
        {
            ActionType = decision.DecisionType,
            Summary = $"Tentativa de recuperação executada para {decision.EntityId}."
        };
    }

    private async Task<ActionExecution> ExecuteAutoRollbackAsync(GovernanceDecision decision, CancellationToken cancellationToken)
    {
        if (!_options.AllowDestructiveActions)
        {
            return new ActionExecution(
                Guid.NewGuid().ToString("N"),
                decision.DecisionType,
                decision.Severity,
                false,
                true,
                "Rollback exige aprovação explícita (AllowDestructiveActions=false).",
                decision.MetadataJson,
                DateTimeOffset.UtcNow);
        }

        var settings = await _settingsStore.ListVersionsAsync(10, cancellationToken);
        var candidate = settings.FirstOrDefault();
        if (candidate is null)
        {
            return new ActionExecution(
                Guid.NewGuid().ToString("N"),
                decision.DecisionType,
                decision.Severity,
                false,
                false,
                "Sem snapshot disponível para rollback.",
                "{}",
                DateTimeOffset.UtcNow);
        }

        await _settingsStore.RestoreVersionAsync(candidate.VersionId, cancellationToken);
        RegisterAction();
        return new ActionExecution(
            Guid.NewGuid().ToString("N"),
            decision.DecisionType,
            decision.Severity,
            true,
            false,
            $"Rollback automático aplicado para settings versão {candidate.VersionId}.",
            JsonSerializer.Serialize(new { restoredVersion = candidate.VersionId }),
            DateTimeOffset.UtcNow);
    }

    private async Task<ActionExecution> ExecuteCanaryRollbackAsync(GovernanceDecision decision, CancellationToken cancellationToken)
    {
        var rules = await _canaryRuleStore.ListAsync(cancellationToken);
        if (rules.Count == 0)
        {
            return new ActionExecution(
                Guid.NewGuid().ToString("N"),
                decision.DecisionType,
                decision.Severity,
                false,
                false,
                "Rollback de canario ignorado: nenhuma regra cadastrada.",
                "{}",
                DateTimeOffset.UtcNow);
        }

        var updated = rules
            .Select(x => x with
            {
                Enabled = false,
                CanaryPercent = 0
            })
            .ToArray();
        await _canaryRuleStore.SaveAsync(updated, cancellationToken);
        RegisterAction();
        return new ActionExecution(
            Guid.NewGuid().ToString("N"),
            decision.DecisionType,
            decision.Severity,
            true,
            false,
            "Rollback instantaneo de canario aplicado (todas as regras desativadas).",
            JsonSerializer.Serialize(new { rulesDisabled = updated.Length }),
            DateTimeOffset.UtcNow);
    }

    private async Task<int> ReplayBotAsync(CancellationToken cancellationToken)
    {
        var count = 0;
        var pending = await _botOutbox.ListPendingAsync(cancellationToken);
        foreach (var command in pending.Take(50))
        {
            await _botPublisher.PublishAsync(command, cancellationToken);
            await _botOutbox.DeleteAsync(command.MessageId, cancellationToken);
            count++;
        }
        return count;
    }

    private async Task<int> ReplayWhatsAppAsync(CancellationToken cancellationToken)
    {
        var count = 0;
        var pending = await _whatsAppOutbox.ListPendingAsync(cancellationToken);
        foreach (var command in pending.Take(50))
        {
            await _whatsAppPublisher.PublishAsync(command, cancellationToken);
            await _whatsAppOutbox.DeleteAsync(command.MessageId, cancellationToken);
            count++;
        }
        return count;
    }

    private async Task<int> ReplayTelegramAsync(CancellationToken cancellationToken)
    {
        var count = 0;
        var pending = await _telegramOutbox.ListPendingAsync(cancellationToken);
        foreach (var command in pending.Take(50))
        {
            await _telegramPublisher.PublishAsync(command, cancellationToken);
            await _telegramOutbox.DeleteAsync(command.MessageId, cancellationToken);
            count++;
        }
        return count;
    }

    private async Task<int> ReplayInstagramAsync(CancellationToken cancellationToken)
    {
        var count = 0;
        var pending = await _instagramOutbox.ListPendingAsync(cancellationToken);
        foreach (var envelope in pending.Take(50))
        {
            switch (envelope.MessageType)
            {
                case "publish":
                    var publish = JsonSerializer.Deserialize<PublishInstagramPostCommand>(envelope.PayloadJson);
                    if (publish is not null)
                    {
                        await _instagramPublisher.PublishAsync(publish, cancellationToken);
                    }
                    break;
                case "comment-reply":
                    var reply = JsonSerializer.Deserialize<ReplyInstagramCommentCommand>(envelope.PayloadJson);
                    if (reply is not null)
                    {
                        await _instagramPublisher.PublishAsync(reply, cancellationToken);
                    }
                    break;
                case "direct-message":
                    var dm = JsonSerializer.Deserialize<SendInstagramDirectMessageCommand>(envelope.PayloadJson);
                    if (dm is not null)
                    {
                        await _instagramPublisher.PublishAsync(dm, cancellationToken);
                    }
                    break;
            }

            await _instagramOutbox.DeleteAsync(envelope.MessageId, cancellationToken);
            count++;
        }
        return count;
    }

    private bool IsCircuitOpen()
    {
        var now = DateTimeOffset.UtcNow;
        var windowStart = now.AddMinutes(-Math.Max(1, _options.ActionWindowMinutes));
        while (_actionWindow.TryPeek(out var ts) && ts < windowStart)
        {
            _actionWindow.TryDequeue(out _);
        }

        return _actionWindow.Count >= Math.Max(1, _options.MaxActionsPerWindow);
    }

    private void RegisterAction()
    {
        _actionWindow.Enqueue(DateTimeOffset.UtcNow);
    }
}
