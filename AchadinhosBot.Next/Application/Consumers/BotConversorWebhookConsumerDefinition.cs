using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class BotConversorWebhookConsumerDefinition : ConsumerDefinition<BotConversorWebhookConsumer>
{
    public BotConversorWebhookConsumerDefinition()
    {
        EndpointName = "bot-conversor-webhook";
        ConcurrentMessageLimit = 4;
    }

    protected override void ConfigureConsumer(
        IReceiveEndpointConfigurator endpointConfigurator,
        IConsumerConfigurator<BotConversorWebhookConsumer> consumerConfigurator,
        IRegistrationContext context)
    {
        endpointConfigurator.PrefetchCount = 8;
        endpointConfigurator.ConcurrentMessageLimit = 4;
        endpointConfigurator.UseMessageRetry(retry => retry.Interval(3, TimeSpan.FromSeconds(10)));
    }
}
