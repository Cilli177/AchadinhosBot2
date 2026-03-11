using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class InstagramOutboundReplayWorker : BackgroundService
{
    private readonly IInstagramOutboundOutboxStore _outboxStore;
    private readonly IInstagramOutboundPublisher _publisher;
    private readonly MessagingOptions _options;

    public InstagramOutboundReplayWorker(
        IInstagramOutboundOutboxStore outboxStore,
        IInstagramOutboundPublisher publisher,
        IOptions<MessagingOptions> options)
    {
        _outboxStore = outboxStore;
        _publisher = publisher;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await FlushAsync(stoppingToken);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(5, _options.OutboxReplayIntervalSeconds)));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await FlushAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task FlushAsync(CancellationToken cancellationToken)
    {
        var pending = await _outboxStore.ListPendingAsync(cancellationToken);
        foreach (var envelope in pending.Take(Math.Max(1, _options.OutboxBatchSize)))
        {
            try
            {
                switch (envelope.MessageType)
                {
                    case nameof(PublishInstagramPostCommand):
                        var publish = JsonSerializer.Deserialize<PublishInstagramPostCommand>(envelope.PayloadJson);
                        if (publish is not null)
                        {
                            await _publisher.PublishAsync(publish, cancellationToken);
                        }
                        break;

                    case nameof(ReplyInstagramCommentCommand):
                        var reply = JsonSerializer.Deserialize<ReplyInstagramCommentCommand>(envelope.PayloadJson);
                        if (reply is not null)
                        {
                            await _publisher.PublishAsync(reply, cancellationToken);
                        }
                        break;

                    case nameof(SendInstagramDirectMessageCommand):
                        var dm = JsonSerializer.Deserialize<SendInstagramDirectMessageCommand>(envelope.PayloadJson);
                        if (dm is not null)
                        {
                            await _publisher.PublishAsync(dm, cancellationToken);
                        }
                        break;
                }

                await _outboxStore.DeleteAsync(envelope.MessageId, cancellationToken);
            }
            catch
            {
                break;
            }
        }
    }
}
