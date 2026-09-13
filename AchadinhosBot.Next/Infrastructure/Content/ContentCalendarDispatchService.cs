using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using MassTransit;

namespace AchadinhosBot.Next.Infrastructure.Content;

public sealed class ContentCalendarDispatchService : IContentCalendarDispatchService
{
    private readonly IBus _bus;
    private readonly IContentCalendarCommandOutboxStore _outbox;

    public ContentCalendarDispatchService(IBus bus, IContentCalendarCommandOutboxStore outbox)
    {
        _bus = bus;
        _outbox = outbox;
    }

    public async Task<ContentCalendarDispatchResult> QueueProcessDueAsync(string actor, CancellationToken ct)
    {
        var command = new ProcessContentCalendarDueCommand
        {
            RequestedBy = actor,
            DeduplicationKey = $"manual:{DateTimeOffset.UtcNow:yyyyMMddHHmm}"
        };
        try
        {
            await PublishAsync(command, ct);
            return new ContentCalendarDispatchResult(command.MessageId, "rabbitmq", false);
        }
        catch
        {
            await _outbox.SaveAsync(new ContentCalendarCommandEnvelope
            {
                MessageId = command.MessageId,
                PayloadJson = JsonSerializer.Serialize(command)
            }, ct);
            return new ContentCalendarDispatchResult(command.MessageId, "local-outbox", true);
        }
    }

    public Task PublishAsync(ProcessContentCalendarDueCommand command, CancellationToken ct) =>
        _bus.Publish(command, context =>
        {
            if (Guid.TryParse(command.MessageId, out var messageId)) context.MessageId = messageId;
            context.Headers.Set("content-calendar-message-id", command.MessageId);
            context.Headers.Set("dedupe-key", command.DeduplicationKey);
        }, ct);
}

public sealed record ContentCalendarDispatchResult(string MessageId, string Mode, bool QueuedInOutbox);
