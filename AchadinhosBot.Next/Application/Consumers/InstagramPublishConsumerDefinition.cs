using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class InstagramPublishConsumerDefinition : ConsumerDefinition<InstagramPublishConsumer>
{
    public InstagramPublishConsumerDefinition()
    {
        EndpointName = "instagram-publish";
        ConcurrentMessageLimit = 1;
    }

    protected override void ConfigureConsumer(
        IReceiveEndpointConfigurator endpointConfigurator,
        IConsumerConfigurator<InstagramPublishConsumer> consumerConfigurator,
        IRegistrationContext context)
    {
        endpointConfigurator.PrefetchCount = 1;
        endpointConfigurator.ConcurrentMessageLimit = 1;
        endpointConfigurator.UseMessageRetry(retry => retry.Interval(5, TimeSpan.FromSeconds(20)));
    }
}
