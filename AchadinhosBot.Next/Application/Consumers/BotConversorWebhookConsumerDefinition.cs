using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class BotConversorWebhookConsumerDefinition : ConsumerDefinition<BotConversorWebhookConsumer>
{
    public BotConversorWebhookConsumerDefinition()
    {
        EndpointName = "bot-conversor-webhook";
        ConcurrentMessageLimit = 1;
    }

    protected override void ConfigureConsumer(
        IReceiveEndpointConfigurator endpointConfigurator,
        IConsumerConfigurator<BotConversorWebhookConsumer> consumerConfigurator,
        IRegistrationContext context)
    {
        endpointConfigurator.PrefetchCount = 1;
        endpointConfigurator.ConcurrentMessageLimit = 1;
        endpointConfigurator.UseMessageRetry(retry => retry.Interval(3, TimeSpan.FromSeconds(10)));
    }
}
