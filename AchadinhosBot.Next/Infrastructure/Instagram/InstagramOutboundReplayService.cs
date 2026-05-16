using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using System.Text.Json;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

/**
 * Background service that periodically checks the local outbox for messages that failed 
 * to reach RabbitMQ and attempts to republish them.
 */
public sealed class InstagramOutboundReplayService : BackgroundService
{
    private const string WorkerName = nameof(InstagramOutboundReplayService);
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<InstagramOutboundReplayService> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromMinutes(10);
    private readonly WorkerActivityTracker _workerActivityTracker;

    public InstagramOutboundReplayService(
        IServiceProvider serviceProvider,
        ILogger<InstagramOutboundReplayService> logger,
        WorkerActivityTracker workerActivityTracker)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _workerActivityTracker = workerActivityTracker;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _workerActivityTracker.MarkStarted(WorkerName);
        _logger.LogInformation("InstagramOutboundReplayService iniciado (Intervalo={Intervalo}).", _checkInterval);
        await ReplayOutboxAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_checkInterval, stoppingToken);
                await ReplayOutboxAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _workerActivityTracker.MarkFailure(WorkerName, ex);
                _logger.LogError(ex, "Erro no ciclo de replay do outbox.");
            }
        }
    }

    private async Task ReplayOutboxAsync(CancellationToken ct)
    {
        using var scope = _serviceProvider.CreateScope();
        var outboxStore = scope.ServiceProvider.GetRequiredService<IInstagramOutboundOutboxStore>();
        var publisher = scope.ServiceProvider.GetRequiredService<IInstagramOutboundPublisher>();

        var pending = await outboxStore.ListPendingAsync(ct);
        if (pending.Count == 0)
        {
            _workerActivityTracker.MarkSuccess(WorkerName);
            return;
        }

        _logger.LogInformation("Encontradas {Count} mensagens pendentes no outbox local para replay.", pending.Count);

        foreach (var envelope in pending)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                if (string.Equals(envelope.MessageType, nameof(PublishInstagramPostCommand), StringComparison.OrdinalIgnoreCase))
                {
                    var command = JsonSerializer.Deserialize<PublishInstagramPostCommand>(envelope.PayloadJson);
                    if (command is not null)
                    {
                        await publisher.PublishAsync(command, ct);
                        await outboxStore.DeleteAsync(envelope.MessageId, ct);
                        _logger.LogInformation("Mensagem {MessageId} (Replay) republicada com sucesso e removida do outbox.", envelope.MessageId);
                    }
                }
                else
                {
                    _logger.LogWarning("Tipo de mensagem desconhecido no outbox: {MessageType}. Ignorando.", envelope.MessageType);
                    // Opcional: deletar se for lixo, mas por seguranca mantemos.
                }
            }
            catch (Exception ex)
            {
                _workerActivityTracker.MarkFailure(WorkerName, ex);
                _logger.LogWarning("Falha ao processar replay para mensagem {MessageId}: {Error}", envelope.MessageId, ex.Message);
            }
        }

        _workerActivityTracker.MarkSuccess(WorkerName);
    }
}
