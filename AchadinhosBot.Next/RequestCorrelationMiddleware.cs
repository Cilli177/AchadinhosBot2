using Serilog.Context;

namespace AchadinhosBot.Next.Infrastructure.Monitoring;

public sealed class RequestCorrelationMiddleware
{
    public const string CorrelationHeaderName = "X-Correlation-ID";
    private readonly RequestDelegate _next;

    public RequestCorrelationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers[CorrelationHeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = context.TraceIdentifier;
        }

        context.TraceIdentifier = correlationId!;
        context.Response.Headers[CorrelationHeaderName] = correlationId;

        using (LogContext.PushProperty("RequestId", context.TraceIdentifier))
        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await _next(context);
        }
    }
}
