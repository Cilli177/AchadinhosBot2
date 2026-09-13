using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Infrastructure.Content;

public sealed class ContentCalendarCommandOutboxReplayWorker : BackgroundService
{
    private readonly IContentCalendarCommandOutboxStore _outbox;
    private readonly ContentCalendarDispatchService _dispatcher;
    private readonly ILogger<ContentCalendarCommandOutboxReplayWorker> _logger;

    public ContentCalendarCommandOutboxReplayWorker(IContentCalendarCommandOutboxStore outbox, ContentCalendarDispatchService dispatcher, ILogger<ContentCalendarCommandOutboxReplayWorker> logger)
    { _outbox = outbox; _dispatcher = dispatcher; _logger = logger; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                foreach (var envelope in await _outbox.ListPendingAsync(stoppingToken))
                {
                    var command = JsonSerializer.Deserialize<ProcessContentCalendarDueCommand>(envelope.PayloadJson);
                    if (command is null) continue;
                    await _dispatcher.PublishAsync(command, stoppingToken);
                    await _outbox.DeleteAsync(envelope.MessageId, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { _logger.LogWarning(ex, "Falha ao reenviar comandos pendentes do calendario de conteudo."); }

            try { await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
