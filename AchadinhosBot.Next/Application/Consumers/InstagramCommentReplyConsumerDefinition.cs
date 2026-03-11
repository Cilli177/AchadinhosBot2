using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class InstagramCommentReplyConsumerDefinition : ConsumerDefinition<InstagramCommentReplyConsumer>
{
    public InstagramCommentReplyConsumerDefinition()
    {
        EndpointName = "instagram-comment-replies";
        ConcurrentMessageLimit = 1;
    }

    protected override void ConfigureConsumer(
        IReceiveEndpointConfigurator endpointConfigurator,
        IConsumerConfigurator<InstagramCommentReplyConsumer> consumerConfigurator,
        IRegistrationContext context)
    {
        endpointConfigurator.PrefetchCount = 1;
        endpointConfigurator.ConcurrentMessageLimit = 1;
        endpointConfigurator.UseMessageRetry(retry => retry.Interval(5, TimeSpan.FromSeconds(15)));
    }
}
