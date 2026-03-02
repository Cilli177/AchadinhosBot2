using Polly;
using Polly.Extensions.Http;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public static class ResiliencyPolicies
{
    public static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy()
    {
        return HttpPolicyExtensions
            .HandleTransientHttpError()
            .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)));
    }
}
