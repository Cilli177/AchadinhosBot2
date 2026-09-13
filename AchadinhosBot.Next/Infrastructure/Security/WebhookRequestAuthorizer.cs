using Microsoft.AspNetCore.Http;

namespace AchadinhosBot.Next.Infrastructure.Security;

public static class WebhookRequestAuthorizer
{
    public static bool IsAuthorized(HttpRequest request, string body, string? webhookSecret, string? fallbackApiKey)
    {
        if (WebhookSignatureVerifier.TryValidate(request, body, webhookSecret))
        {
            return true;
        }

        string[] allowedHeaders = ["x-api-key", "apikey", "Authorization"];
        foreach (var header in allowedHeaders)
        {
            if (!request.Headers.TryGetValue(header, out var providedAuth))
            {
                continue;
            }

            var value = providedAuth.ToString().Trim();
            if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                value = value["Bearer ".Length..].Trim();
            }

            if (SecretComparer.EqualsConstantTime(fallbackApiKey, value))
            {
                return true;
            }
        }

        return false;
    }
}
